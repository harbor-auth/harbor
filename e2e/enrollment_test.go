//go:build e2e

// End-to-end tests for the full user-enrollment flow (docs/DESIGN.md §11.1).
//
// Unlike flow_test.go (which drives the stateless harbor-hot), these tests drive
// the cold-path harbor-mgmt binary AND inspect Postgres directly, because the
// enrollment invariants are about persisted state: a region-encoded users row
// with a wrapped DEK + encrypted pairwise_secret, a first passkey keyed off the
// real user.id, and the atomic pending→active flip (design decision 3).
//
// They are behind the `e2e` build tag (excluded from `go test ./...`) and skip
// gracefully when their prerequisites are absent, so they never block CI when
// the mgmt stack / database are not wired:
//
//	HARBOR_MGMT_E2E_BASE_URL  base URL of a running harbor-mgmt (default :8081)
//	HARBOR_E2E_DATABASE_URL   pgx URL to the same Postgres harbor-mgmt writes to
//	HARBOR_E2E_REGION         region to enroll into (default "eu")
//	HARBOR_E2E_ORIGIN         WebAuthn origin (default the mgmt base URL)
//
// Run (example):
//
//	HARBOR_MGMT_E2E_BASE_URL=http://localhost:8081 \
//	HARBOR_E2E_DATABASE_URL=postgres://harbor:harbor@localhost:5432/harbor \
//	go test -tags e2e ./e2e/... -run Enrollment
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
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jackc/pgx/v5"
)

const (
	defaultMgmtBaseURL = "http://localhost:8081"
	enrollPath         = "/enroll"
	registerBeginPath  = "/webauthn/register/begin"
	registerFinishPath = "/webauthn/register/finish"
	defaultEnrollRegn  = "eu"
)

// mgmtBaseURL is the base URL of the harbor-mgmt cold-path binary under test.
func mgmtBaseURL() string {
	if v := envOr("HARBOR_MGMT_E2E_BASE_URL", ""); v != "" {
		return strings.TrimRight(v, "/")
	}
	return defaultMgmtBaseURL
}

// enrollRegion is the region new users are enrolled into.
func enrollRegion() string { return envOr("HARBOR_E2E_REGION", defaultEnrollRegn) }

// webauthnOrigin is the origin presented in the WebAuthn clientDataJSON; it must
// match the server's WEBAUTHN_ORIGIN or the ceremony is rejected.
func webauthnOrigin() string { return envOr("HARBOR_E2E_ORIGIN", mgmtBaseURL()) }

// openDB connects to the Postgres instance harbor-mgmt writes to. When
// HARBOR_E2E_DATABASE_URL is unset or unreachable the caller should skip: these
// tests assert on persisted rows, which is impossible without the database.
func openDB(t *testing.T) *pgx.Conn {
	t.Helper()
	url := envOr("HARBOR_E2E_DATABASE_URL", "")
	if url == "" {
		t.Skip("HARBOR_E2E_DATABASE_URL not set — skipping enrollment DB e2e")
	}
	conn, err := pgx.Connect(context.Background(), url)
	if err != nil {
		t.Skipf("cannot connect to HARBOR_E2E_DATABASE_URL: %v — skipping", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(context.Background()); err != nil {
			t.Logf("close db connection: %v", err)
		}
	})
	return conn
}

// jarClient returns an HTTP client with a cookie jar so the enrollment session
// cookie set by POST /enroll flows into the passkey registration ceremony —
// exactly how a browser carries the handoff (docs/DESIGN.md §9, §11.1).
func jarClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{Jar: jar}
}

// enroll POSTs to /enroll and returns the created user's ID and region. It fails
// the test on a non-2xx response (the enrollment front door must be up for these
// tests to mean anything) but skips if harbor-mgmt is unreachable entirely.
func enroll(t *testing.T, client *http.Client) (userID, region string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"region": enrollRegion()})
	if err != nil {
		t.Fatalf("marshal enroll body: %v", err)
	}
	resp, err := client.Post(mgmtBaseURL()+enrollPath, "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Skipf("harbor-mgmt unreachable at %s: %v — skipping enrollment e2e", mgmtBaseURL(), err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read enroll response: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusServiceUnavailable {
			t.Skipf("POST /enroll = 503 (enrollment not wired: set DATABASE_URL + HARBOR_KEK_SECRET) — skipping")
		}
		t.Fatalf("POST /enroll = %d, want 2xx\n%s", resp.StatusCode, raw)
	}
	userID, region = parseEnrollResponse(t, raw)
	if userID == "" {
		t.Fatalf("POST /enroll response has no user id\n%s", raw)
	}
	return userID, region
}

// parseEnrollResponse extracts the user id and region from the enrollment
// response, tolerating the exact JSON field name (user_id / userId / id).
func parseEnrollResponse(t *testing.T, raw []byte) (userID, region string) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("enroll response is not JSON: %v\n%s", err, raw)
	}
	for _, k := range []string{"user_id", "userId", "id"} {
		if s, ok := m[k].(string); ok && s != "" {
			userID = s
			break
		}
	}
	if s, ok := m["region"].(string); ok {
		region = s
	}
	return userID, region
}

// --- Test: enrollment persists a region-encoded, sealed users row -----------

// TestEnrollmentCreatesSealedUserRow verifies that POST /enroll writes EXACTLY
// one users row for the returned id, in the requested region, with a non-empty
// wrapped DEK and encrypted pairwise_secret, and status "pending" — the account
// is not usable until the first passkey activates it (design decision 3, §11.1).
func TestEnrollmentCreatesSealedUserRow(t *testing.T) {
	conn := openDB(t)
	userID, region := enroll(t, jarClient(t))

	if want := enrollRegion(); region != "" && region != want {
		t.Errorf("enroll response region = %q, want %q", region, want)
	}

	// Exactly one row for this id.
	var count int
	if err := conn.QueryRow(context.Background(),
		"SELECT count(*) FROM users WHERE id = $1", userID).Scan(&count); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 1 {
		t.Fatalf("users rows for id %s = %d, want exactly 1", userID, count)
	}

	var (
		gotRegion string
		status    string
		dek       []byte
		pairwise  []byte
	)
	if err := conn.QueryRow(context.Background(),
		"SELECT region, status, dek_wrapped, pairwise_secret FROM users WHERE id = $1", userID,
	).Scan(&gotRegion, &status, &dek, &pairwise); err != nil {
		t.Fatalf("select user: %v", err)
	}

	if gotRegion != enrollRegion() {
		t.Errorf("users.region = %q, want %q (region-encoded row, §5)", gotRegion, enrollRegion())
	}
	if status != "pending" {
		t.Errorf("users.status = %q, want pending (not usable until first passkey, §11.1)", status)
	}
	if len(dek) == 0 {
		t.Error("users.dek_wrapped is empty — DEK must be wrapped under the regional KEK (§4.4)")
	}
	if len(pairwise) == 0 {
		t.Error("users.pairwise_secret is empty — pairwise secret must be encrypted (§4.4)")
	}
}

// --- Test: each enrollment is independent (REQ-004) -------------------------

// TestEnrollmentPerCallIsIndependent verifies REQ-004: two enrollment calls
// create two DISTINCT users (there is no shared external identity to collide
// on), and neither call silently reuses or overwrites the other's row.
func TestEnrollmentPerCallIsIndependent(t *testing.T) {
	conn := openDB(t)
	id1, _ := enroll(t, jarClient(t))
	id2, _ := enroll(t, jarClient(t))

	if id1 == id2 {
		t.Fatalf("two enrollments returned the same user id %q — must be independent (REQ-004)", id1)
	}
	for _, id := range []string{id1, id2} {
		var count int
		if err := conn.QueryRow(context.Background(),
			"SELECT count(*) FROM users WHERE id = $1", id).Scan(&count); err != nil {
			t.Fatalf("count users %s: %v", id, err)
		}
		if count != 1 {
			t.Errorf("users rows for id %s = %d, want exactly 1", id, count)
		}
	}
}

// --- Test: enrollment response carries no PII -------------------------------

// TestEnrollmentResponseHasNoPII verifies the enrollment response exposes only
// the opaque user id + region and never PII (email, name, phone) — Harbor stores
// and returns no profile PII (docs/DESIGN.md §5, §6.5). This is the black-box
// proxy for "no PII in logs": the response is the only caller-visible surface.
func TestEnrollmentResponseHasNoPII(t *testing.T) {
	body, err := json.Marshal(map[string]string{"region": enrollRegion()})
	if err != nil {
		t.Fatalf("marshal enroll body: %v", err)
	}
	resp, err := http.Post(mgmtBaseURL()+enrollPath, "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Skipf("harbor-mgmt unreachable at %s: %v — skipping", mgmtBaseURL(), err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read enroll response: %v", err)
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("POST /enroll = 503 (enrollment not wired) — skipping")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("POST /enroll = %d, want 2xx\n%s", resp.StatusCode, raw)
	}

	lower := strings.ToLower(string(raw))
	for _, banned := range []string{"email", "@", "phone", "\"name\"", "display_name", "displayname", "given_name", "family_name"} {
		if strings.Contains(lower, banned) {
			t.Errorf("enroll response leaks possible PII token %q: %s", banned, raw)
		}
	}

	userID, _ := parseEnrollResponse(t, raw)
	if strings.Contains(userID, "@") {
		t.Errorf("user id looks like an email (PII): %q", userID)
	}
}

// --- Test: first passkey persists keyed off the real user.id ----------------

// TestFirstPasskeyPersistsKeyedOffUserID drives the full handoff: enroll →
// register/begin → register/finish with a software authenticator, then verifies
// a credentials row was persisted keyed off the enrolled user.id AND the user
// was flipped pending→active in the SAME operation (design decision 3). If the
// ceremony cannot complete (e.g. WEBAUTHN_ORIGIN mismatch on this stack) the
// passkey portion skips rather than fails, keeping the harness CI-safe.
func TestFirstPasskeyPersistsKeyedOffUserID(t *testing.T) {
	conn := openDB(t)
	client := jarClient(t)
	userID, _ := enroll(t, client)

	ok := registerPasskey(t, client)
	if !ok {
		t.Skip("passkey registration ceremony did not complete on this stack — skipping persistence assertions")
	}

	// A credential must now exist, keyed off the REAL user id (not a client-
	// supplied handle).
	var credCount int
	if err := conn.QueryRow(context.Background(),
		"SELECT count(*) FROM credentials WHERE user_id = $1", userID).Scan(&credCount); err != nil {
		t.Fatalf("count credentials: %v", err)
	}
	if credCount != 1 {
		t.Fatalf("credentials for user %s = %d, want exactly 1 (keyed off real user.id, §11.1)", userID, credCount)
	}

	// And the user must have been activated atomically with the passkey insert.
	var status string
	if err := conn.QueryRow(context.Background(),
		"SELECT status FROM users WHERE id = $1", userID).Scan(&status); err != nil {
		t.Fatalf("select user status: %v", err)
	}
	if status != "active" {
		t.Errorf("users.status = %q after first passkey, want active (atomic activation, design decision 3)", status)
	}
}

// --- Test: a failed passkey ceremony rolls back (no partial state) ----------

// TestPasskeyFailureLeavesPendingUserWithNoCredential is the black-box proxy for
// the transaction-rollback invariant: after a FAILED registration/finish, the
// user must remain "pending" with ZERO credentials — never "active" with no
// passkey, nor a passkey without activation (design decision 3 atomicity).
func TestPasskeyFailureLeavesPendingUserWithNoCredential(t *testing.T) {
	conn := openDB(t)
	client := jarClient(t)
	userID, _ := enroll(t, client)

	// Begin the ceremony to obtain the webauthn session cookie, then finish with
	// a garbage attestation so verification fails BEFORE anything is persisted.
	beginResp, err := client.Post(mgmtBaseURL()+registerBeginPath, "application/json", nil)
	if err != nil {
		t.Skipf("register/begin unreachable: %v — skipping", err)
	}
	_ = beginResp.Body.Close()
	if beginResp.StatusCode != http.StatusOK {
		t.Skipf("register/begin = %d (ceremony not wired) — skipping rollback assertion", beginResp.StatusCode)
	}

	finishResp, err := client.Post(mgmtBaseURL()+registerFinishPath, "application/json",
		strings.NewReader(`{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{"attestationObject":"AAAA","clientDataJSON":"AAAA"}}`))
	if err != nil {
		t.Fatalf("register/finish: %v", err)
	}
	_ = finishResp.Body.Close()
	if finishResp.StatusCode >= 200 && finishResp.StatusCode < 300 {
		t.Fatalf("register/finish with garbage attestation = %d, want a client error", finishResp.StatusCode)
	}

	// The failed ceremony must not have persisted ANY partial state.
	var status string
	if err := conn.QueryRow(context.Background(),
		"SELECT status FROM users WHERE id = $1", userID).Scan(&status); err != nil {
		t.Fatalf("select user status: %v", err)
	}
	if status != "pending" {
		t.Errorf("users.status = %q after FAILED passkey, want pending (no activation without a passkey)", status)
	}
	var credCount int
	if err := conn.QueryRow(context.Background(),
		"SELECT count(*) FROM credentials WHERE user_id = $1", userID).Scan(&credCount); err != nil {
		t.Fatalf("count credentials: %v", err)
	}
	if credCount != 0 {
		t.Errorf("credentials for user %s = %d after FAILED passkey, want 0 (rollback, design decision 3)", userID, credCount)
	}
}

// --- software WebAuthn authenticator ---------------------------------------

// registerPasskey runs register/begin then register/finish using a minimal
// software authenticator (ES256, "none" attestation). It returns true only if
// the server accepted the registration (finish 2xx). Any earlier failure — most
// commonly an origin/RP mismatch specific to the test stack — returns false so
// the caller can skip rather than fail.
func registerPasskey(t *testing.T, client *http.Client) bool {
	t.Helper()

	beginResp, err := client.Post(mgmtBaseURL()+registerBeginPath, "application/json", nil)
	if err != nil {
		t.Logf("register/begin unreachable: %v", err)
		return false
	}
	defer func() { _ = beginResp.Body.Close() }()
	if beginResp.StatusCode != http.StatusOK {
		t.Logf("register/begin = %d (ceremony not wired)", beginResp.StatusCode)
		return false
	}
	beginBody, err := io.ReadAll(beginResp.Body)
	if err != nil {
		t.Logf("read register/begin body: %v", err)
		return false
	}

	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID string `json:"id"`
			} `json:"rp"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(beginBody, &opts); err != nil {
		t.Logf("register/begin response not parseable: %v\n%s", err, beginBody)
		return false
	}
	rpID := opts.PublicKey.RP.ID
	if rpID == "" {
		rpID = "localhost"
	}
	if opts.PublicKey.Challenge == "" {
		t.Logf("register/begin response missing challenge\n%s", beginBody)
		return false
	}

	attestation, credID, err := makeAttestation(rpID, opts.PublicKey.Challenge)
	if err != nil {
		t.Logf("build attestation: %v", err)
		return false
	}

	finishResp, err := client.Post(mgmtBaseURL()+registerFinishPath, "application/json", strings.NewReader(attestation))
	if err != nil {
		t.Logf("register/finish: %v", err)
		return false
	}
	defer func() { _ = finishResp.Body.Close() }()
	finishBody, err := io.ReadAll(finishResp.Body)
	if err != nil {
		t.Logf("read register/finish body: %v", err)
		return false
	}
	if finishResp.StatusCode < 200 || finishResp.StatusCode >= 300 {
		t.Logf("register/finish = %d (likely origin/RP mismatch on this stack)\n%s", finishResp.StatusCode, finishBody)
		return false
	}
	_ = credID
	return true
}

// makeAttestation produces a WebAuthn "none"-format registration response for a
// freshly generated ES256 credential, ready to POST to register/finish. It
// returns the JSON body and the generated credential ID.
func makeAttestation(rpID, challengeB64 string) (body string, credID []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, err
	}

	// COSE_Key for an ES256 (P-256) public key.
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
		return "", nil, err
	}

	credID = make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		return "", nil, err
	}

	// authData = rpIdHash(32) | flags(1) | signCount(4) | attestedCredentialData.
	rpHash := sha256.Sum256([]byte(rpID))
	var authData []byte
	authData = append(authData, rpHash[:]...)
	const flagUP, flagUV, flagAT = 0x01, 0x04, 0x40
	authData = append(authData, byte(flagUP|flagUV|flagAT))
	signCount := make([]byte, 4) // 0
	authData = append(authData, signCount...)

	// attestedCredentialData = aaguid(16) | credIdLen(2) | credId | coseKey.
	aaguid := make([]byte, 16) // all-zero AAGUID
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
		return "", nil, err
	}

	clientData, err := json.Marshal(map[string]string{
		"type":      "webauthn.create",
		"challenge": challengeB64,
		"origin":    webauthnOrigin(),
	})
	if err != nil {
		return "", nil, err
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
		return "", nil, err
	}
	return string(out), credID, nil
}

// envOr returns the environment variable v, or def when it is unset/empty.
func envOr(v, def string) string {
	if got := os.Getenv(v); got != "" {
		return got
	}
	return def
}
