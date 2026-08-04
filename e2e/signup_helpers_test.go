//go:build e2e

// Shared helpers for the signup e2e suite (signup_test.go,
// signup_expiry_replay_test.go, signup_origin_gating_test.go,
// signup_concurrency_test.go): the Secure-cookie-over-http jar, thin
// request/response plumbing, goroutine-safe (plain-error) counterparts of the
// t-based enrollment_test.go/recovery_test.go helpers for use in the
// concurrent-session tests, a wrong-origin attestation builder, and small
// Postgres read helpers.
package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jackc/pgx/v5"
)

// --- cookie handling ---------------------------------------------------

// laxSecureCookieJar is a minimal http.CookieJar that tracks cookies per host
// like the stdlib cookiejar, but — unlike it — resends Secure cookies over
// plain http:// requests. See signup_test.go's package doc comment for why
// this is necessary against the checked-in e2e docker-compose stack. It
// deliberately ignores Path scoping (every cookie in this system uses Path=/
// or Path=/webauthn on the same host); sending a superset of what a real
// browser would is harmless for these tests since no assertion here depends
// on a cookie being withheld due to path.
type laxSecureCookieJar struct {
	mu     sync.Mutex
	byHost map[string]map[string]*http.Cookie
}

func newLaxSecureCookieJar() *laxSecureCookieJar {
	return &laxSecureCookieJar{byHost: make(map[string]map[string]*http.Cookie)}
}

func (j *laxSecureCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	host := u.Hostname()
	m := j.byHost[host]
	if m == nil {
		m = make(map[string]*http.Cookie)
		j.byHost[host] = m
	}
	for _, c := range cookies {
		if c.MaxAge < 0 || (!c.Expires.IsZero() && c.Expires.Before(time.Now())) {
			delete(m, c.Name)
			continue
		}
		stored := *c
		m[c.Name] = &stored
	}
}

func (j *laxSecureCookieJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	m := j.byHost[u.Hostname()]
	out := make([]*http.Cookie, 0, len(m))
	for _, c := range m {
		out = append(out, &http.Cookie{Name: c.Name, Value: c.Value})
	}
	return out
}

// signupJarClient is jarClient's counterpart for this suite: an HTTP client
// whose jar carries Secure cookies across hops even over plain HTTP. Every
// other harness helper (enroll, registerPasskey, registerPasskeyWithKey,
// generateRecoveryCodes, ...) works unmodified with the resulting
// *http.Client since they only ever touch client.Jar through the standard
// http.CookieJar interface.
func signupJarClient(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{Jar: newLaxSecureCookieJar()}
}

// cookieValue returns the current value of the named cookie in client's jar
// for mgmtBaseURL(), or "" if absent.
func cookieValue(t *testing.T, client *http.Client, name string) string {
	t.Helper()
	if client.Jar == nil {
		return ""
	}
	u, err := url.Parse(mgmtBaseURL())
	if err != nil {
		t.Fatalf("parse mgmt base url: %v", err)
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// rawRequest issues method/path with body (if non-empty, as
// application/json) and EXACTLY the given cookies — no jar, no
// auto-negotiated headers. It exists for tests that must present a specific,
// possibly forged or stale, cookie value a real client-side jar would never
// produce (simulating an expired session, or a captured-and-replayed
// request). Skips (never fails) if the target is unreachable.
func rawRequest(t *testing.T, method, path, body string, cookies map[string]string) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, mgmtBaseURL()+path, reader)
	if err != nil {
		t.Fatalf("build %s %s request: %v", method, path, err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for name, value := range cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		unavailable(t, "%s %s unreachable: %v", method, path, err)
	}
	return resp
}

// --- plain-error helpers, safe to call from a goroutine ----------------
//
// testing.T's FailNow/Fatal*/SkipNow/Skip* family must only be called from
// the goroutine running the test function. The concurrent-session tests need
// REAL overlapping requests, so the request-issuing helpers they use from
// spawned goroutines return plain errors instead of calling those methods;
// registerPasskeyWithKey (enrollment_test.go) is already safe to reuse as-is
// since it only ever calls t.Logf.

// httpEnroll is enroll's goroutine-safe counterpart.
func httpEnroll(client *http.Client) (userID, region string, err error) {
	body, err := json.Marshal(map[string]string{"region": enrollRegion()})
	if err != nil {
		return "", "", err
	}
	resp, err := client.Post(mgmtBaseURL()+enrollPath, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("POST %s = %d: %s", enrollPath, resp.StatusCode, raw)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", "", err
	}
	if s, ok := m["user_id"].(string); ok {
		userID = s
	}
	if s, ok := m["region"].(string); ok {
		region = s
	}
	if userID == "" {
		return "", "", fmt.Errorf("POST %s response has no user_id: %s", enrollPath, raw)
	}
	return userID, region, nil
}

// httpGenerateRecoveryCodes is generateRecoveryCodes's goroutine-safe
// counterpart.
func httpGenerateRecoveryCodes(client *http.Client) ([]string, error) {
	req, err := http.NewRequest(http.MethodPost, mgmtBaseURL()+recoveryCodesPath, strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("POST %s = %d: %s", recoveryCodesPath, resp.StatusCode, raw)
	}
	var body struct {
		Codes []string `json:"codes"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	if len(body.Codes) == 0 {
		return nil, fmt.Errorf("POST %s returned no codes", recoveryCodesPath)
	}
	return body.Codes, nil
}

// httpAcknowledgeRecovery is the goroutine-safe counterpart of a
// POST /recovery/acknowledge call.
func httpAcknowledgeRecovery(client *http.Client) error {
	resp, err := client.Post(mgmtBaseURL()+recoveryAcknowledgePath, "application/json", strings.NewReader("{}"))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("POST %s = %d (body unreadable: %w)", recoveryAcknowledgePath, resp.StatusCode, readErr)
		}
		return fmt.Errorf("POST %s = %d: %s", recoveryAcknowledgePath, resp.StatusCode, raw)
	}
	return nil
}

// httpBeginRecovery is beginRecovery's goroutine-safe counterpart.
func httpBeginRecovery(client *http.Client, userID string) (string, error) {
	body, err := json.Marshal(map[string]string{"user_id": userID, "method": "code"})
	if err != nil {
		return "", err
	}
	resp, err := client.Post(mgmtBaseURL()+recoveryBeginPath, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("POST %s = %d: %s", recoveryBeginPath, resp.StatusCode, raw)
	}
	var begin struct {
		RecoveryRequestID string `json:"recovery_request_id"`
	}
	if err := json.Unmarshal(raw, &begin); err != nil {
		return "", err
	}
	if begin.RecoveryRequestID == "" {
		return "", fmt.Errorf("POST %s returned no recovery_request_id", recoveryBeginPath)
	}
	return begin.RecoveryRequestID, nil
}

// httpCompleteRecovery is completeRecovery's goroutine-safe counterpart.
func httpCompleteRecovery(client *http.Client, requestID, code string) error {
	body, err := json.Marshal(map[string]string{"recovery_request_id": requestID, "code": code})
	if err != nil {
		return err
	}
	resp, err := client.Post(mgmtBaseURL()+recoveryCompletePath, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("POST %s = %d (body unreadable: %w)", recoveryCompletePath, resp.StatusCode, readErr)
		}
		return fmt.Errorf("POST %s = %d: %s", recoveryCompletePath, resp.StatusCode, raw)
	}
	return nil
}

// driveFullSignup runs the full happy-path chain (enroll, first passkey,
// recovery codes, acknowledge) using only goroutine-safe helpers, so it can
// run concurrently with another such call. It returns a non-nil error at the
// first step that fails or is not wired on this stack, rather than calling
// any testing.T failure/skip method itself.
func driveFullSignup(t *testing.T, client *http.Client) (userID string, err error) {
	userID, _, err = httpEnroll(client)
	if err != nil {
		return "", err
	}
	ok, _, _ := registerPasskeyWithKey(t, client)
	if !ok {
		return userID, fmt.Errorf("first passkey registration did not complete")
	}
	if _, err := httpGenerateRecoveryCodes(client); err != nil {
		return userID, err
	}
	if err := httpAcknowledgeRecovery(client); err != nil {
		return userID, err
	}
	return userID, nil
}

// --- attestation with a forced origin -----------------------------------

// makeAttestationWithOrigin is enrollment_test.go's makeAttestation with the
// ceremony origin forced to an explicit value, independent of
// HARBOR_E2E_ORIGIN/webauthnOrigin(). It exists solely to build a
// registration response asserting an origin OUTSIDE WEBAUTHN_RP_ORIGINS, so
// the wrong-origin/RP e2e test can prove go-webauthn's origin validation
// rejects it — makeAttestation has no such parameter since every other test
// wants the correctly configured origin.
func makeAttestationWithOrigin(rpID, challengeB64, origin string) (body string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	x := make([]byte, 32)
	y := make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	coseKey := map[int]any{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: x,
		-3: y,
	}
	cosePub, err := cbor.Marshal(coseKey)
	if err != nil {
		return "", err
	}

	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		return "", err
	}

	rpHash := sha256.Sum256([]byte(rpID))
	var authData []byte
	authData = append(authData, rpHash[:]...)
	const flagUP, flagUV, flagAT = 0x01, 0x04, 0x40
	authData = append(authData, byte(flagUP|flagUV|flagAT))
	authData = append(authData, make([]byte, 4)...) // signCount = 0

	aaguid := make([]byte, 16)
	authData = append(authData, aaguid...)
	credLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credLen, uint16(len(credID)))
	authData = append(authData, credLen...)
	authData = append(authData, credID...)
	authData = append(authData, cosePub...)

	attObj, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		return "", err
	}

	clientData, err := json.Marshal(map[string]string{
		"type":      "webauthn.create",
		"challenge": challengeB64,
		"origin":    origin,
	})
	if err != nil {
		return "", err
	}

	credIDB64 := base64.RawURLEncoding.EncodeToString(credID)
	resp := map[string]any{
		"id":    credIDB64,
		"rawId": credIDB64,
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": base64.RawURLEncoding.EncodeToString(attObj),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
		},
	}
	out, err := json.Marshal(resp)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// beginRegistrationOptions is the shape this suite needs from a
// POST /webauthn/register/begin response.
type beginRegistrationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
	} `json:"publicKey"`
}

// parseBeginRegistrationResponse extracts the rpID (defaulting to
// "localhost", matching registerPasskeyWithKey's convention) and challenge
// from a register/begin response body.
func parseBeginRegistrationResponse(raw []byte) (rpID, challenge string, err error) {
	var opts beginRegistrationOptions
	if err := json.Unmarshal(raw, &opts); err != nil {
		return "", "", err
	}
	rpID = opts.PublicKey.RP.ID
	if rpID == "" {
		rpID = "localhost"
	}
	if opts.PublicKey.Challenge == "" {
		return "", "", fmt.Errorf("register/begin response missing challenge")
	}
	return rpID, opts.PublicKey.Challenge, nil
}

// --- audit polling and small DB reads -------------------------------------

// pollAuditEventTypes polls audit_events.event_type for userID until every
// entry in want has appeared or a short deadline elapses. GetSignupSuccess
// (internal/bff/signup.go) emits its audit trail via RecordAsync
// (internal/identity/audit.go), which detaches from the request context and
// fires from a background goroutine, so the rows are not guaranteed to exist
// the instant the HTTP response returns.
func pollAuditEventTypes(t *testing.T, conn *pgx.Conn, userID string, want []string) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var got []string
	for {
		rows, err := conn.Query(context.Background(),
			"SELECT event_type FROM audit_events WHERE user_id = $1 ORDER BY occurred_at", userID)
		if err != nil {
			t.Fatalf("query audit_events: %v", err)
		}
		got = got[:0]
		for rows.Next() {
			var et string
			if err := rows.Scan(&et); err != nil {
				rows.Close()
				t.Fatalf("scan audit_events row: %v", err)
			}
			got = append(got, et)
		}
		rows.Close()
		if hasAllEventTypes(got, want) || time.Now().After(deadline) {
			return got
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func hasAllEventTypes(got, want []string) bool {
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func credentialCount(t *testing.T, conn *pgx.Conn, userID string) int {
	t.Helper()
	var count int
	if err := conn.QueryRow(context.Background(),
		"SELECT count(*) FROM credentials WHERE user_id = $1", userID).Scan(&count); err != nil {
		t.Fatalf("count credentials for %s: %v", userID, err)
	}
	return count
}

func userStatus(t *testing.T, conn *pgx.Conn, userID string) string {
	t.Helper()
	var status string
	if err := conn.QueryRow(context.Background(),
		"SELECT status FROM users WHERE id = $1", userID).Scan(&status); err != nil {
		t.Fatalf("select status for %s: %v", userID, err)
	}
	return status
}
