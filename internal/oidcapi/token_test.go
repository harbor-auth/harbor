package oidcapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// mintCode runs the /authorize happy path and returns the freshly-issued code.
func mintCode(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	res := getAuthorize(t, ts, validAuthorizeQuery())
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", res.StatusCode)
	}
	code := locationQuery(t, res, testRedirectURI).Get("code")
	if code == "" {
		t.Fatalf("no code minted by /authorize")
	}
	return code
}

// validTokenForm returns a well-formed token exchange body for the given code.
func validTokenForm(code string) url.Values {
	f := url.Values{}
	f.Set("grant_type", "authorization_code")
	f.Set("code", code)
	f.Set("redirect_uri", testRedirectURI)
	f.Set("client_id", testClientID)
	f.Set("code_verifier", pkceVerifier)
	return f
}

// postToken POSTs a form-encoded body to /token.
func postToken(t *testing.T, ts *httptest.Server, form url.Values) *http.Response {
	t.Helper()
	res, err := http.PostForm(ts.URL+"/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	return res
}

// assertNoStore fails unless the response forbids caching (docs/DESIGN.md §11.7,
// RFC 6749 §5.1). Checks both Cache-Control: no-store and Pragma: no-cache.
func assertNoStore(t *testing.T, res *http.Response) {
	t.Helper()
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
	if p := res.Header.Get("Pragma"); p != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache (RFC 6749 §5.1)", p)
	}
}

// decodeOAuthErrorCode decodes a JSON OAuth error body and returns its `error`
// code.
func decodeOAuthErrorCode(t *testing.T, res *http.Response) string {
	t.Helper()
	var body struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode oauth error: %v", err)
	}
	return body.Error
}

// Happy round trip: /authorize → code → /token returns tokens with no-store.
func TestToken_HappyRoundTrip(t *testing.T) {
	ts := newFlowServer(t)
	code := mintCode(t, ts)

	res := postToken(t, ts, validTokenForm(code))
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	assertNoStore(t, res)
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
		Scope       string `json:"scope"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if body.AccessToken == "" || body.IDToken == "" {
		t.Fatalf("expected non-empty tokens, got %+v", body)
	}
	if body.TokenType != "Bearer" {
		t.Fatalf("token_type = %q, want Bearer", body.TokenType)
	}
}

// Single-use: exchanging the same code twice yields invalid_grant on reuse.
func TestToken_CodeReuse_InvalidGrant(t *testing.T) {
	ts := newFlowServer(t)
	code := mintCode(t, ts)

	first := postToken(t, ts, validTokenForm(code))
	_ = first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first exchange status = %d, want 200", first.StatusCode)
	}

	second := postToken(t, ts, validTokenForm(code))
	defer func() { _ = second.Body.Close() }()
	if second.StatusCode != http.StatusBadRequest {
		t.Fatalf("reuse status = %d, want 400", second.StatusCode)
	}
	assertNoStore(t, second)
	if errCode := decodeOAuthErrorCode(t, second); errCode != "invalid_grant" {
		t.Fatalf("reuse error = %q, want invalid_grant", errCode)
	}
}

// An unsupported grant_type is rejected with unsupported_grant_type (400).
func TestToken_UnsupportedGrantType(t *testing.T) {
	ts := newFlowServer(t)
	code := mintCode(t, ts)

	form := validTokenForm(code)
	form.Set("grant_type", "client_credentials")

	res := postToken(t, ts, form)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
	assertNoStore(t, res)
	if errCode := decodeOAuthErrorCode(t, res); errCode != "unsupported_grant_type" {
		t.Fatalf("error = %q, want unsupported_grant_type", errCode)
	}
}

// A wrong code_verifier fails PKCE, collapsing to invalid_grant (no leak of the
// specific check that failed).
func TestToken_PKCEMismatch_InvalidGrant(t *testing.T) {
	ts := newFlowServer(t)
	code := mintCode(t, ts)

	form := validTokenForm(code)
	form.Set("code_verifier", "this-is-not-the-right-verifier")

	res := postToken(t, ts, form)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
	assertNoStore(t, res)
	if errCode := decodeOAuthErrorCode(t, res); errCode != "invalid_grant" {
		t.Fatalf("error = %q, want invalid_grant", errCode)
	}
}
