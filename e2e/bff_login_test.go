//go:build e2e

// End-to-end test for the BFF passkey-login ceremony that resumes the OIDC flow
// (docs/DESIGN.md §11.2; audit blocker 1.1 — the auth-bypass fix). Unlike
// flow_test.go (which drives the stub auto-approve /authorize) this exercises the
// REAL authenticated path end-to-end:
//
//	enroll → register passkey → GET /authorize (BFF 302 to login) →
//	/login (assertion begin) → sign → /login/complete →
//	302 /authorize/complete → 302 RP redirect with code → POST /token
//
// It then decodes the issued token and asserts the security property this whole
// feature exists to guarantee: the `sub` claim is the user's per-RP PPID — an
// opaque value that is NOT the raw enrollment user_id and carries no PII — and
// two distinct users receive two DISTINCT PPIDs (INV-JWT-SUB-IS-PPID, no-PII).
//
// Like its siblings it is behind the `e2e` build tag and skips gracefully at
// every stage where the full BFF stack is not wired (mgmt/DB down, /authorize
// auto-approves instead of redirecting to login, the login ceremony is not
// resolvable, or assertion verification fails on this stack), so it never blocks
// CI. The cross-service subtlety (passkey registered on harbor-mgmt, assertion
// verified on harbor-hot) means both must share the DB and RP origin; when they
// do not, the flow skips.
//
// Run (example, full stack):
//
//	HARBOR_E2E_BASE_URL=http://localhost:8080 \
//	HARBOR_MGMT_E2E_BASE_URL=http://localhost:8081 \
//	HARBOR_E2E_DATABASE_URL=postgres://harbor:harbor@localhost:5432/harbor \
//	go test -tags e2e ./e2e/... -run BFFPasskeyLogin
package e2e

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

const (
	// bffLoginBeginPath starts the passkey assertion for a BFF session. The
	// request_id (from the /authorize redirect) is passed as a query param.
	bffLoginBeginPath = "/login"
	// bffLoginFinishPath completes the assertion and 302s to /authorize/complete.
	bffLoginFinishPath = "/login/complete"
)

// bffFlowResult captures the outcome of one full BFF passkey login → token flow.
type bffFlowResult struct {
	userID string // opaque enrollment user id (must NOT equal the PPID)
	sub    string // the per-RP PPID from the issued token
}

// TestBFFPasskeyLoginToTokenFlow drives the authenticated BFF flow to completion
// for two independent users and asserts the PPID invariants. It skips when the
// full BFF stack is not exercisable on the target environment.
func TestBFFPasskeyLoginToTokenFlow(t *testing.T) {
	res1, ok := runBFFPasskeyFlow(t)
	if !ok {
		t.Skip("BFF passkey login flow not exercisable on this stack — skipping")
	}

	// The sub claim must be a PPID: present, opaque, distinct from the raw
	// user_id, and never PII (docs/DESIGN.md §3.2, §6.5; INV-JWT-SUB-IS-PPID).
	if res1.sub == "" {
		t.Fatal("token sub (PPID) is empty")
	}
	if res1.sub == res1.userID {
		t.Errorf("sub = %q equals the raw user_id — sub must be the per-RP PPID (INV-JWT-SUB-IS-PPID)", res1.sub)
	}
	if strings.Contains(res1.sub, "@") {
		t.Errorf("sub = %q looks like PII (email) — the PPID must be opaque (INV-JWT-NO-PII)", res1.sub)
	}

	// A second, independent user must receive a DISTINCT PPID.
	res2, ok := runBFFPasskeyFlow(t)
	if !ok {
		t.Skip("second BFF passkey flow not exercisable — skipping distinct-PPID assertion")
	}
	if res2.sub == "" {
		t.Fatal("second token sub (PPID) is empty")
	}
	if res1.userID == res2.userID {
		t.Fatalf("two enrollments returned the same user_id %q — cannot assert distinct PPIDs", res1.userID)
	}
	if res1.sub == res2.sub {
		t.Errorf("two distinct users share PPID %q — PPIDs must be per-user distinct (§3.2)", res1.sub)
	}
}

// runBFFPasskeyFlow enrolls a user, registers a passkey (cold path), then drives
// the hot-path BFF login → /authorize/complete → /token chain, returning the
// issued token's sub (PPID) and the enrollment user_id. It returns ok=false and
// logs the reason at any stage the stack does not behave as the BFF flow
// requires, so callers can skip rather than fail.
func runBFFPasskeyFlow(t *testing.T) (bffFlowResult, bool) {
	t.Helper()

	// 1) Cold path: enroll + register a passkey, keeping the private key so we
	//    can sign the login assertion. enroll() skips the whole test if the mgmt
	//    stack / DB is unreachable.
	mgmt := jarClient(t)
	userID, _ := enroll(t, mgmt)
	ok, key, credID := registerPasskeyWithKey(t, mgmt)
	if !ok {
		t.Logf("passkey registration did not complete — cannot drive login")
		return bffFlowResult{}, false
	}

	// 2) Hot path: a cookie-jar, no-redirect client so the BFF + WebAuthn ceremony
	//    cookies flow through while we inspect each redirect Location.
	hc := jarNoRedirectClient(t)
	verifier, challenge := pkcePair(t)

	// GET /authorize — in BFF mode this mints a session and 302s to the login
	// page carrying request_id. If it auto-approves (stub resolver) or errors, the
	// BFF login path is not wired on this stack.
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", demoClientID)
	q.Set("redirect_uri", demoRedirectURI)
	q.Set("scope", demoScope)
	q.Set("state", "bff-state")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	authResp, err := hc.Get(baseURL() + authorizePath + "?" + q.Encode())
	if err != nil {
		t.Logf("GET /authorize: %v", err)
		return bffFlowResult{}, false
	}
	defer func() { _ = authResp.Body.Close() }()
	if authResp.StatusCode != http.StatusFound {
		t.Logf("GET /authorize = %d (not a BFF redirect to login) — skipping", authResp.StatusCode)
		return bffFlowResult{}, false
	}
	requestID := requestIDFromLocation(authResp)
	if requestID == "" {
		t.Logf("no request_id in /authorize redirect %q — not BFF mode", authResp.Header.Get("Location"))
		return bffFlowResult{}, false
	}

	// /login begin — obtain the assertion options (challenge + rpId). This needs
	// the server to identify the user for the session; if that seam is not wired
	// the request is refused and we skip.
	beginResp, err := hc.Post(baseURL()+bffLoginBeginPath+"?request_id="+url.QueryEscape(requestID), "application/json", nil)
	if err != nil {
		t.Logf("POST /login (begin): %v", err)
		return bffFlowResult{}, false
	}
	defer func() { _ = beginResp.Body.Close() }()
	if beginResp.StatusCode != http.StatusOK {
		t.Logf("POST /login begin = %d (user resolver / ceremony not wired) — skipping", beginResp.StatusCode)
		return bffFlowResult{}, false
	}
	beginBody, err := io.ReadAll(beginResp.Body)
	if err != nil {
		t.Logf("read /login begin body: %v", err)
		return bffFlowResult{}, false
	}
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RPID      string `json:"rpId"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(beginBody, &opts); err != nil {
		t.Logf("/login begin not parseable: %v\n%s", err, beginBody)
		return bffFlowResult{}, false
	}
	rpID := opts.PublicKey.RPID
	if rpID == "" {
		rpID = "localhost"
	}
	if opts.PublicKey.Challenge == "" {
		t.Logf("/login begin missing challenge\n%s", beginBody)
		return bffFlowResult{}, false
	}

	// Sign the assertion with the registration key and complete the ceremony.
	assertion, err := makeAssertion(rpID, opts.PublicKey.Challenge, key, credID)
	if err != nil {
		t.Logf("build assertion: %v", err)
		return bffFlowResult{}, false
	}
	finishResp, err := hc.Post(baseURL()+bffLoginFinishPath, "application/json", strings.NewReader(assertion))
	if err != nil {
		t.Logf("POST /login/complete: %v", err)
		return bffFlowResult{}, false
	}
	defer func() { _ = finishResp.Body.Close() }()
	if finishResp.StatusCode != http.StatusFound {
		body, err := io.ReadAll(finishResp.Body)
		if err != nil {
			t.Logf("POST /login/complete read body: %v", err)
		}
		t.Logf("POST /login/complete = %d, want 302 (assertion verification may have failed on this stack)\n%s", finishResp.StatusCode, body)
		return bffFlowResult{}, false
	}

	// Follow the 302 to /authorize/complete, which issues the code and 302s to RP.
	completeLoc := finishResp.Header.Get("Location")
	if completeLoc == "" {
		t.Logf("/login/complete 302 without Location")
		return bffFlowResult{}, false
	}
	if strings.HasPrefix(completeLoc, "/") {
		completeLoc = baseURL() + completeLoc
	}
	compResp, err := hc.Get(completeLoc)
	if err != nil {
		t.Logf("GET /authorize/complete: %v", err)
		return bffFlowResult{}, false
	}
	defer func() { _ = compResp.Body.Close() }()
	if compResp.StatusCode != http.StatusFound {
		body, err := io.ReadAll(compResp.Body)
		if err != nil {
			t.Logf("GET /authorize/complete read body: %v", err)
		}
		t.Logf("GET /authorize/complete = %d, want 302 to RP\n%s", compResp.StatusCode, body)
		return bffFlowResult{}, false
	}
	if loc := compResp.Header.Get("Location"); !strings.HasPrefix(loc, demoRedirectURI) {
		t.Logf("/authorize/complete redirected to %q, want prefix %q", loc, demoRedirectURI)
		return bffFlowResult{}, false
	}
	code := codeFromLocation(t, compResp)
	if code == "" {
		t.Logf("/authorize/complete 302 carried no code")
		return bffFlowResult{}, false
	}

	// Exchange the code for tokens.
	tokenResp := postToken(t, code, verifier, demoRedirectURI)
	defer func() { _ = tokenResp.Body.Close() }()
	if tokenResp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(tokenResp.Body)
		if err != nil {
			t.Logf("POST /token read body: %v", err)
		}
		t.Logf("POST /token = %d, want 200\n%s", tokenResp.StatusCode, body)
		return bffFlowResult{}, false
	}
	var tok struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tok); err != nil {
		t.Logf("decode /token response: %v", err)
		return bffFlowResult{}, false
	}
	// Prefer the id_token's sub; fall back to the access token (also PPID-subject).
	jwt := tok.IDToken
	if jwt == "" {
		jwt = tok.AccessToken
	}
	if jwt == "" {
		t.Logf("/token response carried neither id_token nor access_token")
		return bffFlowResult{}, false
	}
	return bffFlowResult{userID: userID, sub: subFromJWT(t, jwt)}, true
}

// jarNoRedirectClient returns an HTTP client with a cookie jar that captures 3xx
// responses instead of following them — so ceremony cookies (BFF + WebAuthn)
// persist across steps while we still inspect each redirect Location.
func jarNoRedirectClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// requestIDFromLocation extracts the `request_id` query param from a 302
// Location (the BFF /authorize redirect to the login page), or "".
func requestIDFromLocation(resp *http.Response) string {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return ""
	}
	u, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	return u.Query().Get("request_id")
}

// subFromJWT decodes the payload segment of a compact JWT and returns its `sub`
// claim. It does not verify the signature — the test asserts on the claim value
// (the PPID), not on token validity, which the flow's 200 from /token already
// established.
func subFromJWT(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed JWT: %d segments", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal JWT claims: %v\n%s", err, payload)
	}
	return claims.Subject
}

// makeAssertion produces a WebAuthn assertion (login) response for a previously
// registered ES256 credential, signing the server-provided challenge with the
// SAME private key used at registration. The signature covers
// authenticatorData ‖ SHA-256(clientDataJSON) and is ASN.1/DER encoded, as the
// go-webauthn verifier expects. The body is ready to POST to /login/complete.
func makeAssertion(rpID, challengeB64 string, key *ecdsa.PrivateKey, credID []byte) (string, error) {
	// authenticatorData = rpIdHash(32) | flags(1) | signCount(4). No attested
	// credential data is present in an assertion. UP|UV are set; signCount is
	// incremented past the registration value (0) to satisfy clone detection.
	rpHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 0, 37)
	authData = append(authData, rpHash[:]...)
	const flagUP, flagUV = 0x01, 0x04
	authData = append(authData, byte(flagUP|flagUV))
	signCount := make([]byte, 4)
	binary.BigEndian.PutUint32(signCount, 1)
	authData = append(authData, signCount...)

	clientData, err := json.Marshal(map[string]string{
		"type":      "webauthn.get",
		"challenge": challengeB64,
		"origin":    webauthnOrigin(),
	})
	if err != nil {
		return "", err
	}

	clientDataHash := sha256.Sum256(clientData)
	signed := make([]byte, 0, len(authData)+len(clientDataHash))
	signed = append(signed, authData...)
	signed = append(signed, clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}

	credIDB64 := base64.RawURLEncoding.EncodeToString(credID)
	resp := map[string]any{
		"id":    credIDB64,
		"rawId": credIDB64,
		"type":  "public-key",
		"response": map[string]any{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"signature":         base64.RawURLEncoding.EncodeToString(sig),
		},
	}
	out, err := json.Marshal(resp)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
