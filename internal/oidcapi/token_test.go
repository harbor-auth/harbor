package oidcapi

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/openapi"
	"github.com/harbor-auth/harbor/internal/oidc"

	oidctest "github.com/harbor-auth/harbor/internal/testsupport/oidc"
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

func postTokenWithBasic(t *testing.T, ts *httptest.Server, form url.Values, clientID, secret string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", basicAuthHeader(clientID, secret))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	return res
}

func newClientAuthFlowServer(t *testing.T, method, secret string) *httptest.Server {
	t.Helper()
	clients := oidctest.NewInMemoryClientRegistry()
	client := oidc.Client{
		ID:                      testClientID,
		SectorID:                "localhost",
		RedirectURIs:            []string{testRedirectURI},
		ScopesAllowed:           []string{"openid", "profile"},
		TokenEndpointAuthMethod: method,
	}
	if secret != "" {
		hash := sha256.Sum256([]byte(secret))
		client.SecretHash = hash[:]
	}
	clients.Put(client)
	signer, err := crypto.NewLocalSigner()
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	svc := oidctest.NewService(t, oidc.ServiceConfig{
		Issuer: "https://eu.harbor.id", Clients: clients,
		Codes: oidctest.NewInMemoryAuthCodeStore(), Tokens: oidc.NewJWTIssuer(oidc.JWTIssuerConfig{Signer: signer}),
		Sessions: oidctest.NewStubSessionResolver("demo-subject-ppid"),
	})
	srv := New(Config{Issuer: "https://eu.harbor.id", Service: svc, Signers: []crypto.Signer{signer}})
	ts := httptest.NewServer(openapi.HandlerFromMux(srv, http.NewServeMux()))
	t.Cleanup(ts.Close)
	return ts
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

func TestToken_ClientAuthenticationMatchesRegisteredMethod(t *testing.T) {
	const secret = "high-entropy-client-secret"
	for _, tc := range []struct {
		name        string
		registered  string
		basic       bool
		basicSecret string
		formSecret  string
		wantStatus  int
	}{
		{name: "public none", registered: "none", wantStatus: http.StatusOK},
		{name: "basic correct", registered: "client_secret_basic", basic: true, wantStatus: http.StatusOK},
		{name: "basic wrong secret", registered: "client_secret_basic", basic: true, basicSecret: "wrong-secret", wantStatus: http.StatusUnauthorized},
		{name: "post correct", registered: "client_secret_post", formSecret: secret, wantStatus: http.StatusOK},
		{name: "basic client rejects post", registered: "client_secret_basic", formSecret: secret, wantStatus: http.StatusUnauthorized},
		{name: "post client rejects basic", registered: "client_secret_post", basic: true, wantStatus: http.StatusUnauthorized},
		{name: "confidential missing secret", registered: "client_secret_basic", wantStatus: http.StatusUnauthorized},
		{name: "unsupported registered method", registered: "private_key_jwt", basic: true, wantStatus: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := newClientAuthFlowServer(t, tc.registered, secret)
			code := mintCode(t, ts)
			form := validTokenForm(code)
			if tc.formSecret != "" {
				form.Set("client_secret", tc.formSecret)
			}
			var res *http.Response
			if tc.basic {
				presented := tc.basicSecret
				if presented == "" {
					presented = secret
				}
				res = postTokenWithBasic(t, ts, form, testClientID, presented)
			} else {
				res = postToken(t, ts, form)
			}
			defer func() { _ = res.Body.Close() }()
			if res.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", res.StatusCode, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusUnauthorized {
				assertNoStore(t, res)
				if got := decodeOAuthErrorCode(t, res); got != "invalid_client" {
					t.Fatalf("error = %q, want invalid_client", got)
				}
			}
		})
	}
}

func TestToken_BasicAndPostCredentialsConflict(t *testing.T) {
	const secret = "high-entropy-client-secret"
	ts := newClientAuthFlowServer(t, "client_secret_basic", secret)
	code := mintCode(t, ts)
	form := validTokenForm(code)
	form.Set("client_id", "different-client")
	form.Set("client_secret", secret)

	res := postTokenWithBasic(t, ts, form, testClientID, secret)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
	if got := decodeOAuthErrorCode(t, res); got != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", got)
	}
}
