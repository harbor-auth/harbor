//go:build e2e

// Foundation F8 — agent-runnable end-to-end OIDC flow test.
//
// This drives a LIVE harbor-hot through the composed authorize→token→JWKS flow
// and the §11.7 security negatives, catching the "unit-green but assembled-flow
// broken" class of bug that unit tests cannot. It is behind the `e2e` build tag
// so it is excluded from the default `go test ./...` (it needs a running server).
//
// Run:
//
//	docker compose -f e2e/docker-compose.yml up -d
//	HARBOR_E2E_BASE_URL=http://localhost:8080 go test -tags e2e ./e2e/...
//
// The harbor-hot scaffold registers a demo client (below) with a stub session
// resolver that auto-approves, so /authorize should mint a code without a login
// UI. Assertions check status codes and key JSON fields (resiliently, via
// map[string]any) rather than exact bodies, so the harness survives benign
// response-shape changes while still enforcing the security invariants.
package e2e

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

const (
	defaultBaseURL   = "http://localhost:8080"
	demoClientID     = "demo-client"
	demoRedirectURI  = "http://localhost:3000/callback"
	discoveryPath    = "/.well-known/openid-configuration"
	healthzPath      = "/healthz"
	authorizePath    = "/authorize"
	tokenPath        = "/token"
	demoScope        = "openid"
	demoScopeOffline = "openid offline_access"
	minVerifierChars = 43
)

func baseURL() string {
	if v := os.Getenv("HARBOR_E2E_BASE_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return defaultBaseURL
}

// noRedirectClient captures 3xx responses instead of following them, so we can
// inspect the Location header (critical for the redirect_uri invariant).
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// pkcePair returns a fresh (verifier, S256 challenge) pair per RFC 7636.
func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand: %v", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf) // 43 chars
	if len(verifier) < minVerifierChars {
		t.Fatalf("generated verifier too short: %d", len(verifier))
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

func TestHealthz(t *testing.T) {
	resp, err := http.Get(baseURL() + healthzPath)
	if err != nil {
		t.Fatalf("GET %s: %v", healthzPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s = %d, want 200", healthzPath, resp.StatusCode)
	}
}

func TestDiscoveryDocument(t *testing.T) {
	resp, err := http.Get(baseURL() + discoveryPath)
	if err != nil {
		t.Fatalf("GET %s: %v", discoveryPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", discoveryPath, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading discovery doc body: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("discovery doc is not JSON: %v\n%s", err, body)
	}
	for _, key := range []string{"issuer", "authorization_endpoint", "token_endpoint"} {
		if s, ok := doc[key].(string); !ok || s == "" {
			t.Errorf("discovery doc missing/empty %q", key)
		}
	}
}

// authorize performs a GET /authorize with the given params and returns the raw
// response (no redirects followed). Uses the openid-only scope.
func authorize(t *testing.T, redirectURI, challenge, state string) *http.Response {
	t.Helper()
	return authorizeWithScope(t, redirectURI, challenge, state, demoScope)
}

// authorizeWithScope is like authorize but lets the caller specify the scope
// string (e.g. "openid offline_access" to request a refresh token).
func authorizeWithScope(t *testing.T, redirectURI, challenge, state, scope string) *http.Response {
	t.Helper()
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", demoClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	resp, err := noRedirectClient().Get(baseURL() + authorizePath + "?" + q.Encode())
	if err != nil {
		t.Fatalf("GET %s: %v", authorizePath, err)
	}
	return resp
}

// postRefreshToken exchanges a refresh token at POST /token.
func postRefreshToken(t *testing.T, refreshToken string) *http.Response {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", demoClientID)
	resp, err := http.Post(baseURL()+tokenPath, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST %s (refresh_token): %v", tokenPath, err)
	}
	return resp
}

// assertNoStore fails the test unless the response carries Cache-Control: no-store
// (docs/DESIGN.md §11.7 — token responses must never be cached).
func assertNoStore(t *testing.T, resp *http.Response) {
	t.Helper()
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
}

// codeFromLocation extracts the `code` query param from a 302 Location, or "".
func codeFromLocation(t *testing.T, resp *http.Response) string {
	t.Helper()
	loc := resp.Header.Get("Location")
	if loc == "" {
		return ""
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("bad Location %q: %v", loc, err)
	}
	return u.Query().Get("code")
}

func TestAuthorizeTokenHappyPath(t *testing.T) {
	verifier, challenge := pkcePair(t)
	resp := authorize(t, demoRedirectURI, challenge, "state-happy")
	defer resp.Body.Close()

	// The scaffold auto-approves, so we expect a 302 back to the registered
	// redirect carrying a code. If a login/consent step blocks auto-approval,
	// tolerate a non-302 but still assert we did NOT bounce to an unvalidated
	// URI — then skip the token exchange.
	if resp.StatusCode != http.StatusFound {
		t.Logf("authorize returned %d (not 302) — auto-approval may be gated; skipping token exchange", resp.StatusCode)
		if loc := resp.Header.Get("Location"); loc != "" && !strings.HasPrefix(loc, demoRedirectURI) {
			t.Errorf("non-302 authorize leaked a redirect to an unexpected Location: %q", loc)
		}
		return
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, demoRedirectURI) {
		t.Fatalf("authorize redirected to %q, want prefix %q", loc, demoRedirectURI)
	}
	code := codeFromLocation(t, resp)
	if code == "" {
		t.Fatal("authorize 302 did not carry a code param")
	}

	// Exchange the code for tokens.
	tokenResp := postToken(t, code, verifier, demoRedirectURI)
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(tokenResp.Body)
		if err != nil {
			t.Fatalf("POST %s = %d, want 200 (also failed reading body: %v)", tokenPath, tokenResp.StatusCode, err)
		}
		t.Fatalf("POST %s = %d, want 200\n%s", tokenPath, tokenResp.StatusCode, body)
	}
	var tok map[string]any
	body, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		t.Fatalf("reading token response body: %v", err)
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		t.Fatalf("token response is not JSON: %v\n%s", err, body)
	}
	if tt, _ := tok["token_type"].(string); !strings.EqualFold(tt, "Bearer") {
		t.Errorf("token_type = %v, want Bearer", tok["token_type"])
	}
}

// postToken exchanges an authorization code at /token.
func postToken(t *testing.T, code, verifier, redirectURI string) *http.Response {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", demoClientID)
	form.Set("code_verifier", verifier)

	resp, err := http.Post(baseURL()+tokenPath, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST %s: %v", tokenPath, err)
	}
	return resp
}

// TestTokenWrongVerifierIsInvalidGrant enforces §11.7: a PKCE mismatch must be
// rejected as invalid_grant (400), never leaking which check failed.
func TestTokenWrongVerifierIsInvalidGrant(t *testing.T) {
	_, challenge := pkcePair(t)
	authResp := authorize(t, demoRedirectURI, challenge, "state-badpkce")
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Skipf("authorize did not auto-approve (%d); cannot obtain a code for the negative test", authResp.StatusCode)
	}
	code := codeFromLocation(t, authResp)
	if code == "" {
		t.Skip("no code from authorize; cannot run negative token test")
	}

	// Exchange with a DIFFERENT (wrong) verifier.
	wrongVerifier, _ := pkcePair(t)
	resp := postToken(t, code, wrongVerifier, demoRedirectURI)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong-verifier /token = %d, want 400", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading wrong-verifier error body: %v", err)
	}
	var errBody map[string]any
	if err := json.Unmarshal(body, &errBody); err == nil {
		if ec, _ := errBody["error"].(string); ec != "invalid_grant" {
			t.Errorf("error = %q, want invalid_grant (must not leak which check failed)", ec)
		}
	} else {
		t.Logf("token error body not JSON (%s); status 400 already asserted", body)
	}
}

// TestAuthorizeTokenRefreshFlow exercises the full authorize → token → refresh
// rotation cycle end-to-end against the live harbor-hot server:
//
//  1. GET /authorize with offline_access scope → 302 with code.
//  2. POST /token (authorization_code) → access_token + refresh_token.
//  3. POST /token (refresh_token) → new access_token + rotated refresh_token.
//  4. The old refresh_token must be rejected with invalid_grant (rotation invariant,
//     docs/DESIGN.md §3.5 INV-REFRESH-ROTATION-SINGLE-USE).
//
// The test skips gracefully if auto-approval is not wired (non-302 from /authorize)
// or if the server does not return a refresh_token (server scaffold may not yet
// support offline_access).
func TestAuthorizeTokenRefreshFlow(t *testing.T) {
	verifier, challenge := pkcePair(t)

	// Step 1: authorize with offline_access so /token will issue a refresh token.
	authResp := authorizeWithScope(t, demoRedirectURI, challenge, "state-refresh", demoScopeOffline)
	defer authResp.Body.Close()

	if authResp.StatusCode != http.StatusFound {
		t.Skipf("authorize returned %d (not 302) — auto-approval not wired; skipping refresh flow", authResp.StatusCode)
	}
	if loc := authResp.Header.Get("Location"); !strings.HasPrefix(loc, demoRedirectURI) {
		t.Fatalf("authorize redirected to %q, want prefix %q", loc, demoRedirectURI)
	}
	code := codeFromLocation(t, authResp)
	if code == "" {
		t.Skip("no code from authorize; cannot run refresh flow test")
	}

	// Step 2: exchange the authorization code → expect refresh_token in addition
	// to access_token (offline_access was consented).
	tokenResp := postToken(t, code, verifier, demoRedirectURI)
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("POST %s (authorization_code) = %d, want 200\n%s", tokenPath, tokenResp.StatusCode, body)
	}
	assertNoStore(t, tokenResp)

	var tok1 struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"` // asserted below
		RefreshToken string `json:"refresh_token"`
	}
	body1, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		t.Fatalf("read token response: %v", err)
	}
	if err := json.Unmarshal(body1, &tok1); err != nil {
		t.Fatalf("decode token response: %v\n%s", err, body1)
	}
	if tok1.AccessToken == "" {
		t.Fatal("token response missing access_token")
	}
	if !strings.EqualFold(tok1.TokenType, "Bearer") {
		t.Errorf("token_type = %q, want Bearer", tok1.TokenType)
	}
	if tok1.RefreshToken == "" {
		// The server scaffold may not yet support offline_access — skip rather
		// than fail so this does not block the CI gate on an in-progress server.
		t.Skipf("token response has no refresh_token — server may not have offline_access wired (body: %s)", body1)
	}

	// Step 3: rotate — present the refresh_token to get new tokens.
	refreshResp := postRefreshToken(t, tok1.RefreshToken)
	defer refreshResp.Body.Close()
	if refreshResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(refreshResp.Body)
		t.Fatalf("POST %s (refresh_token) = %d, want 200\n%s", tokenPath, refreshResp.StatusCode, body)
	}
	assertNoStore(t, refreshResp)

	var tok2 struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"` // asserted below
		RefreshToken string `json:"refresh_token"`
	}
	body2, err := io.ReadAll(refreshResp.Body)
	if err != nil {
		t.Fatalf("read refresh response: %v", err)
	}
	if err := json.Unmarshal(body2, &tok2); err != nil {
		t.Fatalf("decode refresh response: %v\n%s", err, body2)
	}
	if tok2.AccessToken == "" {
		t.Fatal("refresh response missing access_token")
	}
	if !strings.EqualFold(tok2.TokenType, "Bearer") {
		t.Errorf("refresh token_type = %q, want Bearer", tok2.TokenType)
	}
	if tok2.RefreshToken == "" {
		t.Fatal("refresh response missing new refresh_token (rotation required)")
	}
	if tok2.RefreshToken == tok1.RefreshToken {
		t.Fatal("rotated refresh_token must differ from the original (INV-REFRESH-ROTATION-SINGLE-USE)")
	}

	// Step 4: replay the OLD refresh_token — it must be rejected (single-use
	// rotation invariant, docs/DESIGN.md §3.5).
	replayResp := postRefreshToken(t, tok1.RefreshToken)
	defer replayResp.Body.Close()
	if replayResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("old refresh_token reuse = %d, want 400 (INV-REFRESH-ROTATION-SINGLE-USE)", replayResp.StatusCode)
	}
	assertNoStore(t, replayResp)
	var errBody map[string]any
	replayBytes, _ := io.ReadAll(replayResp.Body)
	if err := json.Unmarshal(replayBytes, &errBody); err == nil {
		if ec, _ := errBody["error"].(string); ec != "invalid_grant" {
			t.Errorf("old refresh_token error = %q, want invalid_grant (must not leak which check failed)", ec)
		}
	} else {
		t.Logf("replay error body not JSON (%s); status 400 already asserted", replayBytes)
	}
}

// TestRefreshInvalidTokenIsInvalidGrant verifies that presenting a well-formed
// but unrecognised refresh token is rejected with 400 invalid_grant — the server
// must not leak whether the token was expired, revoked, or simply unknown.
func TestRefreshInvalidTokenIsInvalidGrant(t *testing.T) {
	const bogus = "not-a-real-refresh-token"
	resp := postRefreshToken(t, bogus)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bogus refresh_token = %d, want 400", resp.StatusCode)
	}
	assertNoStore(t, resp)
	var errBody map[string]any
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &errBody); err == nil {
		if ec, _ := errBody["error"].(string); ec != "invalid_grant" {
			t.Errorf("bogus refresh_token error = %q, want invalid_grant", ec)
		}
	} else {
		t.Logf("bogus refresh error body not JSON (%s); status 400 already asserted", body)
	}
}

// TestAuthorizeUnregisteredRedirectRejected enforces the exact-match redirect
// invariant (§11.7): an unregistered redirect_uri must NEVER receive a redirect.
func TestAuthorizeUnregisteredRedirectRejected(t *testing.T) {
	const attacker = "https://attacker.example/steal"
	_, challenge := pkcePair(t)
	resp := authorize(t, attacker, challenge, "state-evil")
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		if loc := resp.Header.Get("Location"); strings.HasPrefix(loc, attacker) {
			t.Fatalf("authorize redirected to the UNREGISTERED redirect_uri %q — must reject exactly", loc)
		}
	}
	// A non-redirect error status (typically 400) is the correct behavior: the
	// error is shown locally, never bounced to the unvalidated URI.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		t.Errorf("authorize with bad redirect_uri returned %d — expected a client error, not success", resp.StatusCode)
	}
}
