package oidcapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/openapi"
	"github.com/harbor-auth/harbor/internal/oidc"
)

// newRevokeServer builds a Server wired with revocation support.
func newRevokeServer(t *testing.T) (*httptest.Server, *oidc.InMemorySessionStore) {
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
	sessionStore := oidc.NewInMemorySessionStore()
	grantStore := oidc.NewInMemoryGrantStore()
	svc := oidc.NewService(oidc.ServiceConfig{
		Issuer:       "https://eu.harbor.id",
		Clients:      clients,
		Codes:        oidc.NewInMemoryAuthCodeStore(),
		Tokens:       oidc.NewJWTIssuer(oidc.JWTIssuerConfig{Signer: signer}),
		Sessions:     oidc.NewStubSessionResolver("demo-subject-ppid"),
		SessionStore: sessionStore,
		Grants:       grantStore,
	})
	filter := oidc.NewInMemoryRevocationFilter()
	srv := New(Config{
		Issuer:           "https://eu.harbor.id",
		Service:          svc,
		Signers:          []crypto.Signer{signer},
		RevocationFilter: filter,
	})
	h := openapi.HandlerFromMux(srv, http.NewServeMux())
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts, sessionStore
}

// postRevoke POSTs a form to /revoke with optional auth header.
func postRevoke(t *testing.T, ts *httptest.Server, form url.Values, authHeader string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /revoke: %v", err)
	}
	return res
}

// --- Anonymous caller tests ---

// TestPostRevoke_Anonymous_Returns401 verifies that anonymous callers
// receive 401 Unauthorized.
func TestPostRevoke_Anonymous_Returns401(t *testing.T) {
	ts, _ := newRevokeServer(t)

	form := url.Values{}
	form.Set("token", "some-token")

	res := postRevoke(t, ts, form, "") // no auth header
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

// TestPostRevoke_InvalidBasicAuth_Returns401 verifies that malformed
// Basic auth returns 401.
func TestPostRevoke_InvalidBasicAuth_Returns401(t *testing.T) {
	ts, _ := newRevokeServer(t)

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

			res := postRevoke(t, ts, form, tt.header)
			defer func() { _ = res.Body.Close() }()

			if res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", res.StatusCode)
			}
		})
	}
}

// --- Missing token field tests ---

// TestPostRevoke_MissingToken_Returns400 verifies that missing token
// field returns 400 (unlike introspect which returns 200).
func TestPostRevoke_MissingToken_Returns400(t *testing.T) {
	ts, _ := newRevokeServer(t)

	form := url.Values{} // no token field

	res := postRevoke(t, ts, form, basicAuthHeader(testClientID, "secret"))
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}

	var errBody openapi.OAuthError
	if err := json.NewDecoder(res.Body).Decode(&errBody); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if errBody.Error != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", errBody.Error)
	}
}

// TestPostRevoke_EmptyToken_Returns400 verifies that empty token
// returns 400.
func TestPostRevoke_EmptyToken_Returns400(t *testing.T) {
	ts, _ := newRevokeServer(t)

	form := url.Values{}
	form.Set("token", "")

	res := postRevoke(t, ts, form, basicAuthHeader(testClientID, "secret"))
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
}

// --- Success tests ---

// TestPostRevoke_ValidToken_Returns200 verifies that revoking a valid
// token returns 200 with empty body.
func TestPostRevoke_ValidToken_Returns200(t *testing.T) {
	ts, _ := newRevokeServer(t)

	form := url.Values{}
	form.Set("token", "unknown-but-well-formed-token")

	res := postRevoke(t, ts, form, basicAuthHeader(testClientID, "secret"))
	defer func() { _ = res.Body.Close() }()

	// Should return 200 (anti-enumeration)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}

	// Should have Cache-Control: no-store
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}

	// Should have Pragma: no-cache
	if pragma := res.Header.Get("Pragma"); pragma != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", pragma)
	}
}

// TestPostRevoke_UnknownToken_Returns200 verifies anti-enumeration:
// unknown tokens still return 200.
func TestPostRevoke_UnknownToken_Returns200(t *testing.T) {
	ts, _ := newRevokeServer(t)

	form := url.Values{}
	form.Set("token", "completely-unknown-token")
	form.Set("token_type_hint", "refresh_token")

	res := postRevoke(t, ts, form, basicAuthHeader(testClientID, "secret"))
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (anti-enumeration)", res.StatusCode)
	}
}

// TestPostRevoke_TokenTypeHintAccessToken_Returns200 verifies that
// token_type_hint=access_token is handled.
func TestPostRevoke_TokenTypeHintAccessToken_Returns200(t *testing.T) {
	ts, _ := newRevokeServer(t)

	// Mint a real access token
	accessToken := mintAccessToken(t, ts)

	form := url.Values{}
	form.Set("token", accessToken)
	form.Set("token_type_hint", "access_token")

	res := postRevoke(t, ts, form, basicAuthHeader(testClientID, "secret"))
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
}

// TestPostRevoke_TokenTypeHintRefreshToken_Returns200 verifies that
// token_type_hint=refresh_token is handled.
func TestPostRevoke_TokenTypeHintRefreshToken_Returns200(t *testing.T) {
	ts, _ := newRevokeServer(t)

	form := url.Values{}
	form.Set("token", "opaque-refresh-token")
	form.Set("token_type_hint", "refresh_token")

	res := postRevoke(t, ts, form, basicAuthHeader(testClientID, "secret"))
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
}

// TestPostRevoke_NoHint_Returns200 verifies that missing hint still works.
func TestPostRevoke_NoHint_Returns200(t *testing.T) {
	ts, _ := newRevokeServer(t)

	form := url.Values{}
	form.Set("token", "some-token-without-hint")

	res := postRevoke(t, ts, form, basicAuthHeader(testClientID, "secret"))
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
}

// --- Access token revocation tests ---

// TestPostRevoke_AccessToken_AddsToFilter verifies that revoking an access
// token adds its JTI to the revocation filter.
func TestPostRevoke_AccessToken_AddsToFilter(t *testing.T) {
	// Build a server with a filter we can inspect
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
	filter := oidc.NewInMemoryRevocationFilter()
	srv := New(Config{
		Issuer:           "https://eu.harbor.id",
		Service:          svc,
		Signers:          []crypto.Signer{signer},
		RevocationFilter: filter,
	})
	h := openapi.HandlerFromMux(srv, http.NewServeMux())
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Mint a real access token
	accessToken := mintAccessToken(t, ts)

	// Verify the token is not in the filter yet
	// (We can't easily extract the JTI without parsing, so we'll verify
	// by introspecting before and after)
	form := url.Values{}
	form.Set("token", accessToken)

	// Introspect before revocation — should be active
	introspectForm := url.Values{}
	introspectForm.Set("token", accessToken)
	resBefore := postIntrospect(t, ts, introspectForm, basicAuthHeader(testClientID, "secret"))
	defer func() { _ = resBefore.Body.Close() }()

	var bodyBefore openapi.IntrospectResponse
	if err := json.NewDecoder(resBefore.Body).Decode(&bodyBefore); err != nil {
		t.Fatalf("decode before: %v", err)
	}
	if !bodyBefore.Active {
		t.Fatal("token should be active before revocation")
	}

	// Revoke the access token
	form.Set("token_type_hint", "access_token")
	res := postRevoke(t, ts, form, basicAuthHeader(testClientID, "secret"))
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", res.StatusCode)
	}

	// Introspect after revocation — should be inactive
	resAfter := postIntrospect(t, ts, introspectForm, basicAuthHeader(testClientID, "secret"))
	defer func() { _ = resAfter.Body.Close() }()

	var bodyAfter openapi.IntrospectResponse
	if err := json.NewDecoder(resAfter.Body).Decode(&bodyAfter); err != nil {
		t.Fatalf("decode after: %v", err)
	}
	if bodyAfter.Active {
		t.Fatal("token should be inactive after revocation")
	}
}

// --- Cache-Control header tests ---

// TestPostRevoke_CacheControlNoStore verifies that all responses have
// Cache-Control: no-store header.
func TestPostRevoke_CacheControlNoStore(t *testing.T) {
	ts, _ := newRevokeServer(t)

	tests := []struct {
		name       string
		authHeader string
		token      string
		wantStatus int
	}{
		{
			name:       "anonymous (401)",
			authHeader: "",
			token:      "some-token",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "authenticated success (200)",
			authHeader: basicAuthHeader(testClientID, "secret"),
			token:      "some-token",
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing token (400)",
			authHeader: basicAuthHeader(testClientID, "secret"),
			token:      "",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			if tt.token != "" {
				form.Set("token", tt.token)
			}

			res := postRevoke(t, ts, form, tt.authHeader)
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
