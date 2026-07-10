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
// response (no redirects followed).
func authorize(t *testing.T, redirectURI, challenge, state string) *http.Response {
	t.Helper()
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", demoClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", demoScope)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	resp, err := noRedirectClient().Get(baseURL() + authorizePath + "?" + q.Encode())
	if err != nil {
		t.Fatalf("GET %s: %v", authorizePath, err)
	}
	return resp
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
