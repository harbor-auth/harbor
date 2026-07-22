package oidcapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harbor/harbor/internal/crypto"
	"github.com/harbor/harbor/internal/gen/openapi"
	"github.com/harbor/harbor/internal/oidc"
)

// newIntrospectServer builds a Server wired with introspection support.
func newIntrospectServer(t *testing.T) *httptest.Server {
	t.Helper()
	clients := oidc.NewInMemoryClientRegistry()
	clients.Put(oidc.Client{
		ID:            testClientID,
		SectorID:      "localhost",
		RedirectURIs:  []string{testRedirectURI},
		ScopesAllowed: []string{"openid", "profile", "email", "offline_access"},
	})
	signer, err := crypto.NewLocalSigner()
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	svc := oidc.NewService(oidc.ServiceConfig{
		Issuer:   "https://eu.harbor.id",
		Clients:  clients,
		Codes:    oidc.NewInMemoryAuthCodeStore(),
		Tokens:   oidc.NewJWTIssuer(oidc.JWTIssuerConfig{Signer: signer}),
		Sessions: oidc.NewStubSessionResolver("demo-subject-ppid"),
	})
	srv := New(Config{
		Issuer:  "https://eu.harbor.id",
		Service: svc,
		Signers: []crypto.Signer{signer},
	})
	h := openapi.HandlerFromMux(srv, http.NewServeMux())
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

// basicAuthHeader returns a Basic Authorization header value.
func basicAuthHeader(clientID, secret string) string {
	creds := clientID + ":" + secret
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}

// postIntrospect POSTs a form to /introspect with optional auth header.
func postIntrospect(t *testing.T, ts *httptest.Server, form url.Values, authHeader string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	return res
}

// --- Anonymous caller tests ---

// TestPostIntrospect_Anonymous_Returns401 verifies that anonymous callers
// receive 401 Unauthorized.
func TestPostIntrospect_Anonymous_Returns401(t *testing.T) {
	ts := newIntrospectServer(t)

	form := url.Values{}
	form.Set("token", "some-token")

	res := postIntrospect(t, ts, form, "") // no auth header
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}

	// Should have WWW-Authenticate header
	if wwwAuth := res.Header.Get("WWW-Authenticate"); !strings.Contains(wwwAuth, "Basic") {
		t.Fatalf("WWW-Authenticate = %q, want Basic realm", wwwAuth)
	}

	// Should have Cache-Control: no-store
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}

	var errBody openapi.OAuthError
	if err := json.NewDecoder(res.Body).Decode(&errBody); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if errBody.Error != "invalid_client" {
		t.Fatalf("error = %q, want invalid_client", errBody.Error)
	}
}

// --- Invalid Basic auth tests ---

// TestPostIntrospect_InvalidBasicAuth_Returns401 verifies that malformed
// Basic auth returns 401.
func TestPostIntrospect_InvalidBasicAuth_Returns401(t *testing.T) {
	ts := newIntrospectServer(t)

	tests := []struct {
		name   string
		header string
	}{
		{
			name:   "bearer instead of basic",
			header: "Bearer some-token",
		},
		{
			name:   "invalid base64",
			header: "Basic not-valid-base64!!!",
		},
		{
			name:   "missing colon",
			header: "Basic " + base64.StdEncoding.EncodeToString([]byte("no-colon")),
		},
		{
			name:   "empty client_id",
			header: "Basic " + base64.StdEncoding.EncodeToString([]byte(":secret")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			form.Set("token", "some-token")

			res := postIntrospect(t, ts, form, tt.header)
			defer func() { _ = res.Body.Close() }()

			if res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", res.StatusCode)
			}
		})
	}
}

// --- Valid Basic auth tests ---

// TestPostIntrospect_ValidBasicAuth_Proceeds verifies that valid Basic auth
// allows the request to proceed (returns 200 with inactive for unknown token).
func TestPostIntrospect_ValidBasicAuth_Proceeds(t *testing.T) {
	ts := newIntrospectServer(t)

	form := url.Values{}
	form.Set("token", "unknown-token")

	res := postIntrospect(t, ts, form, basicAuthHeader(testClientID, "any-secret"))
	defer func() { _ = res.Body.Close() }()

	// Should proceed past auth — returns 200 with inactive
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}

	var body openapi.IntrospectResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Active {
		t.Fatal("expected active=false for unknown token")
	}
}

// --- Missing token field tests ---

// TestPostIntrospect_MissingToken_ReturnsInactive verifies that missing token
// field returns 200 with active=false (not an error, per RFC 7662).
func TestPostIntrospect_MissingToken_ReturnsInactive(t *testing.T) {
	ts := newIntrospectServer(t)

	form := url.Values{} // no token field

	res := postIntrospect(t, ts, form, basicAuthHeader(testClientID, "secret"))
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}

	var body openapi.IntrospectResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Active {
		t.Fatal("expected active=false for missing token")
	}
}

// TestPostIntrospect_EmptyToken_ReturnsInactive verifies that empty token
// returns 200 with active=false.
func TestPostIntrospect_EmptyToken_ReturnsInactive(t *testing.T) {
	ts := newIntrospectServer(t)

	form := url.Values{}
	form.Set("token", "")

	res := postIntrospect(t, ts, form, basicAuthHeader(testClientID, "secret"))
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}

	var body openapi.IntrospectResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Active {
		t.Fatal("expected active=false for empty token")
	}
}

// --- Active response tests ---

// TestPostIntrospect_ActiveToken_IncludesAllClaims verifies that introspecting
// a valid token returns active=true with all expected claims.
func TestPostIntrospect_ActiveToken_IncludesAllClaims(t *testing.T) {
	ts := newIntrospectServer(t)

	// Mint a real access token
	accessToken := mintAccessToken(t, ts)

	form := url.Values{}
	form.Set("token", accessToken)

	res := postIntrospect(t, ts, form, basicAuthHeader(testClientID, "secret"))
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}

	var body openapi.IntrospectResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if !body.Active {
		t.Fatal("expected active=true for valid token")
	}

	// Verify all claims are present
	if body.Sub == nil || *body.Sub == "" {
		t.Fatal("expected non-empty sub claim")
	}
	if body.ClientId == nil || *body.ClientId == "" {
		t.Fatal("expected non-empty client_id claim")
	}
	if body.Scope == nil || *body.Scope == "" {
		t.Fatal("expected non-empty scope claim")
	}
	if body.Exp == nil {
		t.Fatal("expected exp claim")
	}
	if body.Iat == nil {
		t.Fatal("expected iat claim")
	}
	if body.Jti == nil || *body.Jti == "" {
		t.Fatal("expected non-empty jti claim")
	}
	if body.TokenType == nil || *body.TokenType != "Bearer" {
		t.Fatalf("token_type = %v, want Bearer", body.TokenType)
	}
}

// --- Cache-Control header tests ---

// TestPostIntrospect_CacheControlNoStore verifies that all responses have
// Cache-Control: no-store header.
func TestPostIntrospect_CacheControlNoStore(t *testing.T) {
	ts := newIntrospectServer(t)

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{
			name:       "anonymous (401)",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "authenticated inactive (200)",
			authHeader: basicAuthHeader(testClientID, "secret"),
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			form.Set("token", "some-token")

			res := postIntrospect(t, ts, form, tt.authHeader)
			defer func() { _ = res.Body.Close() }()

			if res.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", res.StatusCode, tt.wantStatus)
			}

			if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", cc)
			}
		})
	}
}

// TestPostIntrospect_ActiveResponse_CacheControlNoStore verifies Cache-Control
// on active token responses.
func TestPostIntrospect_ActiveResponse_CacheControlNoStore(t *testing.T) {
	ts := newIntrospectServer(t)
	accessToken := mintAccessToken(t, ts)

	form := url.Values{}
	form.Set("token", accessToken)

	res := postIntrospect(t, ts, form, basicAuthHeader(testClientID, "secret"))
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}

	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
}

// --- Content-Type tests ---

// TestPostIntrospect_ContentTypeJSON verifies that all responses have
// Content-Type: application/json.
func TestPostIntrospect_ContentTypeJSON(t *testing.T) {
	ts := newIntrospectServer(t)

	form := url.Values{}
	form.Set("token", "some-token")

	// Authenticated request
	res := postIntrospect(t, ts, form, basicAuthHeader(testClientID, "secret"))
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}

	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}

// --- token_type_hint tests ---

// TestPostIntrospect_TokenTypeHint verifies that token_type_hint is accepted.
func TestPostIntrospect_TokenTypeHint(t *testing.T) {
	ts := newIntrospectServer(t)
	accessToken := mintAccessToken(t, ts)

	form := url.Values{}
	form.Set("token", accessToken)
	form.Set("token_type_hint", "access_token")

	res := postIntrospect(t, ts, form, basicAuthHeader(testClientID, "secret"))
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}

	var body openapi.IntrospectResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Active {
		t.Fatal("expected active=true")
	}
}

// --- Cross-client isolation tests ---

// TestPostIntrospect_CrossClient_ReturnsInactive verifies that a client cannot
// introspect tokens issued to a different client (aud mismatch).
func TestPostIntrospect_CrossClient_ReturnsInactive(t *testing.T) {
	ts := newIntrospectServer(t)

	// Mint a token for testClientID
	accessToken := mintAccessToken(t, ts)

	// Try to introspect with a different client
	form := url.Values{}
	form.Set("token", accessToken)

	// Use a different client_id in Basic auth
	res := postIntrospect(t, ts, form, basicAuthHeader("other-client", "secret"))
	defer func() { _ = res.Body.Close() }()

	// Should return 200 with active=false (cross-client isolation)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}

	var body openapi.IntrospectResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Active {
		t.Fatal("expected active=false for cross-client introspection")
	}
}
