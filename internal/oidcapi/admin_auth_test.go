package oidcapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/openapi"
)

// spyHandler is a next-handler stub that records whether it was called and
// always writes 200 OK. Tests use it to assert that the middleware either
// passed the request through (called == true) or short-circuited (called ==
// false) without reaching the inner handler.
type spyHandler struct {
	called bool
}

func (s *spyHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	s.called = true
	w.WriteHeader(http.StatusOK)
}

// bearerReq builds a GET or POST request to path. When authHeader is non-empty
// it is set as the Authorization header; otherwise the header is absent.
func bearerReq(method, path, authHeader string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	if authHeader != "" {
		r.Header.Set("Authorization", authHeader)
	}
	return r
}

// decodeAdminError decodes the response body into the generated Error envelope.
func decodeAdminError(t *testing.T, rec *httptest.ResponseRecorder) openapi.Error {
	t.Helper()
	var e openapi.Error
	if err := json.NewDecoder(rec.Body).Decode(&e); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	return e
}

// adminBufLogger returns a slog.Logger that writes into buf for log capture.
func adminBufLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// oneCred builds a single-credential Credentials slice labeled "operator",
// matching production's ADMIN_API_TOKEN wiring, for tests that only care
// about single-token accept/reject behavior.
func oneCred(token string) []AdminCredential {
	return []AdminCredential{{Label: "operator", Token: token}}
}

// withAdminPaths is a test-local path dispatcher that applies mw only when the
// request path is in paths, and falls through to base otherwise. It mirrors the
// behavior that WithAdminAuth (task 4) will provide, allowing these tests to
// assert non-admin-path passthrough without depending on that future function.
func withAdminPaths(base http.Handler, paths []string, mw func(http.Handler) http.Handler) http.Handler {
	set := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		set[p] = struct{}{}
	}
	protected := mw(base)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := set[r.URL.Path]; ok {
			protected.ServeHTTP(w, r)
			return
		}
		base.ServeHTTP(w, r)
	})
}

// --- AdminAuthMiddleware unit tests ---

// TestAdminAuthMiddleware_NoHeader verifies that a request with no
// Authorization header is rejected with 401 and the inner handler is not
// invoked.
func TestAdminAuthMiddleware_NoHeader(t *testing.T) {
	spy := &spyHandler{}
	mw := AdminAuthMiddleware(AdminAuthConfig{Credentials: oneCred("secret-token")})
	rec := httptest.NewRecorder()
	mw(spy).ServeHTTP(rec, bearerReq(http.MethodPost, "/admin/keys/rotate", ""))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if spy.called {
		t.Fatal("inner handler must NOT be invoked on missing Authorization header")
	}
}

// TestAdminAuthMiddleware_WrongToken verifies that a wrong Bearer token is
// rejected with 401 and the inner handler (e.g. the rotator) is NOT invoked.
func TestAdminAuthMiddleware_WrongToken(t *testing.T) {
	spy := &spyHandler{}
	mw := AdminAuthMiddleware(AdminAuthConfig{Credentials: oneCred("correct-token")})
	rec := httptest.NewRecorder()
	mw(spy).ServeHTTP(rec, bearerReq(http.MethodPost, "/admin/keys/rotate", "Bearer wrong-token"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if spy.called {
		t.Fatal("inner handler (rotator) must NOT be invoked on wrong token")
	}
}

// TestAdminAuthMiddleware_CorrectToken verifies that a request with the correct
// Bearer token is forwarded to the inner handler and the middleware does not
// short-circuit it.
func TestAdminAuthMiddleware_CorrectToken(t *testing.T) {
	const tok = "super-secret-admin-token"
	spy := &spyHandler{}
	mw := AdminAuthMiddleware(AdminAuthConfig{Credentials: oneCred(tok)})
	rec := httptest.NewRecorder()
	mw(spy).ServeHTTP(rec, bearerReq(http.MethodPost, "/admin/keys/rotate", "Bearer "+tok))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !spy.called {
		t.Fatal("inner handler must be invoked when correct token is presented")
	}
}

// TestAdminAuthMiddleware_EmptyConfigToken verifies the fail-closed contract:
// when AdminAuthConfig.Token is empty the middleware rejects every request with
// 401, even if the client presents a Bearer token.
func TestAdminAuthMiddleware_EmptyConfigToken(t *testing.T) {
	cases := []struct {
		name   string
		header string
	}{
		{"no header", ""},
		{"empty bearer value", "Bearer "},
		{"non-empty bearer", "Bearer some-token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spy := &spyHandler{}
			mw := AdminAuthMiddleware(AdminAuthConfig{Credentials: oneCred("")})
			rec := httptest.NewRecorder()
			mw(spy).ServeHTTP(rec, bearerReq(http.MethodPost, "/admin/keys/rotate", tc.header))

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (fail-closed when Token is empty)", rec.Code)
			}
			if spy.called {
				t.Fatal("inner handler must NOT be invoked when Token is empty (fail-closed)")
			}
		})
	}
}

// TestAdminAuthMiddleware_BearerCaseInsensitive verifies that the "Bearer"
// scheme prefix is matched case-insensitively per RFC 7235 §2.1.
func TestAdminAuthMiddleware_BearerCaseInsensitive(t *testing.T) {
	const tok = "my-admin-token"
	prefixes := []string{"Bearer", "bearer", "BEARER", "bEaReR"}

	for _, prefix := range prefixes {
		t.Run(prefix, func(t *testing.T) {
			spy := &spyHandler{}
			mw := AdminAuthMiddleware(AdminAuthConfig{Credentials: oneCred(tok)})
			rec := httptest.NewRecorder()
			mw(spy).ServeHTTP(rec, bearerReq(http.MethodPost, "/admin/keys/rotate", prefix+" "+tok))

			if rec.Code != http.StatusOK {
				t.Fatalf("prefix %q: status = %d, want 200", prefix, rec.Code)
			}
			if !spy.called {
				t.Fatalf("prefix %q: inner handler must be called with correct token", prefix)
			}
		})
	}
}

// TestAdminAuthMiddleware_WWWAuthenticateHeader verifies that a 401 response
// carries a WWW-Authenticate header with the correct Bearer challenge
// (RFC 6750 §3).
func TestAdminAuthMiddleware_WWWAuthenticateHeader(t *testing.T) {
	cases := []struct {
		name   string
		header string
	}{
		{"no header", ""},
		{"wrong token", "Bearer wrong"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mw := AdminAuthMiddleware(AdminAuthConfig{Credentials: oneCred("tok")})
			rec := httptest.NewRecorder()
			mw(&spyHandler{}).ServeHTTP(rec, bearerReq(http.MethodPost, "/admin/revoke-jwt", tc.header))

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			got := rec.Header().Get("WWW-Authenticate")
			want := `Bearer error="invalid_token"`
			if got != want {
				t.Fatalf("WWW-Authenticate = %q, want %q", got, want)
			}
		})
	}
}

// TestAdminAuthMiddleware_ErrorResponseShape verifies the 401 body is the
// standard PII-free JSON error envelope used throughout oidcapi.
func TestAdminAuthMiddleware_ErrorResponseShape(t *testing.T) {
	mw := AdminAuthMiddleware(AdminAuthConfig{Credentials: oneCred("tok")})
	rec := httptest.NewRecorder()
	mw(&spyHandler{}).ServeHTTP(rec, bearerReq(http.MethodPost, "/admin/keys/rotate", "Bearer wrong"))

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	e := decodeAdminError(t, rec)
	if e.Code != "invalid_token" {
		t.Fatalf("error.code = %q, want %q", e.Code, "invalid_token")
	}
	if e.Message == "" {
		t.Fatal("error.message must not be empty")
	}
}

// TestAdminAuthMiddleware_TokenNotLogged verifies that the configured and
// presented token values never appear in log output (docs/DESIGN.md §6.5 —
// no secrets in logs).
func TestAdminAuthMiddleware_TokenNotLogged(t *testing.T) {
	const secret = "ultra-secret-value"
	var buf bytes.Buffer
	mw := AdminAuthMiddleware(AdminAuthConfig{
		Credentials: oneCred(secret),
		Logger:      adminBufLogger(&buf),
	})
	handler := mw(&spyHandler{})

	cases := []struct {
		name   string
		header string
	}{
		{"no header", ""},
		{"wrong token", "Bearer wrong-value"},
		{"correct token", "Bearer " + secret},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, bearerReq(http.MethodPost, "/admin/keys/rotate", tc.header))
			if bytes.Contains(buf.Bytes(), []byte(secret)) {
				t.Errorf("token appeared in log output: %s", buf.String())
			}
		})
	}
}

// --- Integration tests through the real openapi.HandlerFromMux router ---

// newTestServer returns a minimal oidcapi.Server suitable for router
// integration tests (no rotator, no revoke store — handlers return 501/503).
func newTestServer(t *testing.T) *Server {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return New(Config{
		Issuer:  "https://eu.harbor.id",
		Signers: []crypto.Signer{crypto.NewSignerFromKey(priv)},
	})
}

// TestAdminAuth_ThroughRouter_RotateEndpoint verifies that the middleware
// correctly guards POST /admin/keys/rotate through the full
// openapi.HandlerFromMux router:
//   - no token    → 401  (middleware rejects before handler runs)
//   - wrong token → 401  (middleware rejects; rotator NOT invoked)
//   - correct token → 501 (middleware passes through; rotator nil → 501, not 401)
func TestAdminAuth_ThroughRouter_RotateEndpoint(t *testing.T) {
	const tok = "admin-rotate-token"
	srv := newTestServer(t)
	base := openapi.HandlerFromMux(srv, http.NewServeMux())
	mw := AdminAuthMiddleware(AdminAuthConfig{Credentials: oneCred(tok)})
	h := withAdminPaths(base, []string{"/admin/keys/rotate", "/admin/revoke-jwt"}, mw)

	ts := httptest.NewServer(h)
	defer ts.Close()

	cases := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"wrong token", "Bearer wrong", http.StatusUnauthorized},
		// Correct token → middleware passes; handler returns 501 (no rotator configured).
		{"correct token", "Bearer " + tok, http.StatusNotImplemented},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, ts.URL+"/admin/keys/rotate", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			_ = res.Body.Close()
			if res.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", res.StatusCode, tc.wantStatus)
			}
		})
	}
}

// TestAdminAuth_ThroughRouter_RevokeJwtEndpoint verifies that the middleware
// correctly guards POST /admin/revoke-jwt through the full router:
//   - no token    → 401
//   - wrong token → 401
//   - correct token → 400 (middleware passes; handler validates body → bad request)
func TestAdminAuth_ThroughRouter_RevokeJwtEndpoint(t *testing.T) {
	const tok = "admin-revoke-token"
	srv := newTestServer(t)
	base := openapi.HandlerFromMux(srv, http.NewServeMux())
	mw := AdminAuthMiddleware(AdminAuthConfig{Credentials: oneCred(tok)})
	h := withAdminPaths(base, []string{"/admin/keys/rotate", "/admin/revoke-jwt"}, mw)

	ts := httptest.NewServer(h)
	defer ts.Close()

	cases := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"wrong token", "Bearer wrong", http.StatusUnauthorized},
		// Correct token → middleware passes; handler checks s.revoked == nil → 503.
		// Status is NOT 401, which proves the handler was reached (middleware passed).
		{"correct token reaches handler", "Bearer " + tok, http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, ts.URL+"/admin/revoke-jwt", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			_ = res.Body.Close()
			if res.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", res.StatusCode, tc.wantStatus)
			}
		})
	}
}

// TestAdminAuth_NonAdminPathsUnaffected verifies that /token, /jwks.json, and
// /healthz are NOT gated by AdminAuthMiddleware when the dispatcher only applies
// it to /admin/* paths — unauthenticated requests reach those endpoints freely.
func TestAdminAuth_NonAdminPathsUnaffected(t *testing.T) {
	const tok = "admin-token"
	srv := newTestServer(t)
	base := openapi.HandlerFromMux(srv, http.NewServeMux())
	mw := AdminAuthMiddleware(AdminAuthConfig{Credentials: oneCred(tok)})
	// Only admin paths are protected; all others fall through to base unchanged.
	h := withAdminPaths(base, []string{"/admin/keys/rotate", "/admin/revoke-jwt"}, mw)

	ts := httptest.NewServer(h)
	defer ts.Close()

	// These non-admin endpoints must be reachable without any Authorization header.
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/healthz"},
		{http.MethodGet, "/jwks.json"},
		{http.MethodGet, "/.well-known/openid-configuration"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, ts.URL+tc.path, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			// Intentionally no Authorization header.
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			_ = res.Body.Close()
			if res.StatusCode == http.StatusUnauthorized {
				t.Fatalf("path %s: got 401 — non-admin path must not require auth", tc.path)
			}
		})
	}
}

// TestAdminAuth_NonAdminPathsWithNoToken_TokenEndpoint verifies that POST
// /token returns a non-401 status without an Authorization header. The endpoint
// returns 400 (malformed form body) rather than 401 because no auth is required.
func TestAdminAuth_NonAdminPathsWithNoToken_TokenEndpoint(t *testing.T) {
	srv := newTestServer(t)
	base := openapi.HandlerFromMux(srv, http.NewServeMux())
	mw := AdminAuthMiddleware(AdminAuthConfig{Credentials: oneCred("admin-tok")})
	h := withAdminPaths(base, []string{"/admin/keys/rotate", "/admin/revoke-jwt"}, mw)

	ts := httptest.NewServer(h)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/token", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode == http.StatusUnauthorized {
		t.Fatalf("POST /token returned 401 — /token must not require admin auth")
	}
}

// --- adminBearerToken unit tests ---

// TestAdminBearerToken_Absent verifies that missing/non-Bearer headers return "".
func TestAdminBearerToken_Absent(t *testing.T) {
	cases := []struct {
		name   string
		header string
	}{
		{"no header", ""},
		{"basic auth", "Basic dXNlcjpwYXNz"},
		{"digest", "Digest username=\"foo\""},
		{"just Bearer word", "Bearer"},
		{"empty bearer value", "Bearer "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			if got := adminBearerToken(r); got != "" {
				t.Fatalf("adminBearerToken = %q, want empty string", got)
			}
		})
	}
}

// TestAdminBearerToken_Present verifies that a Bearer header is extracted
// correctly, including trimming surrounding whitespace.
func TestAdminBearerToken_Present(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"standard", "Bearer mytoken", "mytoken"},
		{"lowercase scheme", "bearer mytoken", "mytoken"},
		{"uppercase scheme", "BEARER mytoken", "mytoken"},
		{"token with hyphens", "Bearer my-long-token-value", "my-long-token-value"},
		{"token with trailing space", "Bearer mytoken ", "mytoken"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Authorization", tc.header)
			if got := adminBearerToken(r); got != tc.want {
				t.Fatalf("adminBearerToken = %q, want %q", got, tc.want)
			}
		})
	}
}

// --- multi-credential (operator + cloud-proxy) tests ---

// twoCreds returns the operator/cloud-proxy credential set harbor-hot wires
// in production: ADMIN_API_TOKEN labeled "operator", MGMT_HOT_PROXY_TOKEN
// labeled "cloud-proxy".
func twoCreds(operatorTok, cloudProxyTok string) []AdminCredential {
	return []AdminCredential{
		{Label: "operator", Token: operatorTok},
		{Label: "cloud-proxy", Token: cloudProxyTok},
	}
}

// TestAdminAuthMiddleware_MultiCredential_BothAccepted verifies that either
// the operator token or the cloud-proxy token is independently sufficient to
// pass the middleware — neither credential depends on the other.
func TestAdminAuthMiddleware_MultiCredential_BothAccepted(t *testing.T) {
	const operatorTok, proxyTok = "operator-token-value", "cloud-proxy-token-value"
	mw := AdminAuthMiddleware(AdminAuthConfig{Credentials: twoCreds(operatorTok, proxyTok)})

	for _, tok := range []string{operatorTok, proxyTok} {
		t.Run(tok, func(t *testing.T) {
			spy := &spyHandler{}
			rec := httptest.NewRecorder()
			mw(spy).ServeHTTP(rec, bearerReq(http.MethodPost, "/admin/keys/rotate", "Bearer "+tok))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if !spy.called {
				t.Fatal("inner handler must be invoked for a valid credential")
			}
		})
	}
}

// TestAdminAuthMiddleware_MultiCredential_NeitherMatches verifies that a
// token matching neither configured credential is rejected with 401 and the
// inner handler is not invoked.
func TestAdminAuthMiddleware_MultiCredential_NeitherMatches(t *testing.T) {
	mw := AdminAuthMiddleware(AdminAuthConfig{Credentials: twoCreds("operator-token", "cloud-proxy-token")})
	spy := &spyHandler{}
	rec := httptest.NewRecorder()
	mw(spy).ServeHTTP(rec, bearerReq(http.MethodPost, "/admin/keys/rotate", "Bearer neither-of-the-above"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if spy.called {
		t.Fatal("inner handler must NOT be invoked when no configured credential matches")
	}
}

// TestAdminAuthMiddleware_MultiCredential_LabelsCredentialInLog verifies that
// an accepted request's log line records which credential label matched
// (docs/DESIGN.md: leaking one credential must be distinguishable from
// leaking the other) and that a rejected request's log line carries no
// credential label at all.
func TestAdminAuthMiddleware_MultiCredential_LabelsCredentialInLog(t *testing.T) {
	const operatorTok, proxyTok = "operator-token-value", "cloud-proxy-token-value"
	var buf bytes.Buffer
	mw := AdminAuthMiddleware(AdminAuthConfig{
		Credentials: twoCreds(operatorTok, proxyTok),
		Logger:      adminBufLogger(&buf),
	})
	handler := mw(&spyHandler{})

	buf.Reset()
	handler.ServeHTTP(httptest.NewRecorder(), bearerReq(http.MethodPost, "/admin/keys/rotate", "Bearer "+operatorTok))
	if !strings.Contains(buf.String(), "credential=operator") {
		t.Errorf("log output for operator token = %q, want it to contain credential=operator", buf.String())
	}

	buf.Reset()
	handler.ServeHTTP(httptest.NewRecorder(), bearerReq(http.MethodPost, "/admin/keys/rotate", "Bearer "+proxyTok))
	if !strings.Contains(buf.String(), "credential=cloud-proxy") {
		t.Errorf("log output for cloud-proxy token = %q, want it to contain credential=cloud-proxy", buf.String())
	}

	buf.Reset()
	handler.ServeHTTP(httptest.NewRecorder(), bearerReq(http.MethodPost, "/admin/keys/rotate", "Bearer wrong-token"))
	if strings.Contains(buf.String(), "credential=") {
		t.Errorf("log output for a rejected request = %q, must not carry a credential label", buf.String())
	}
}

// TestAdminAuthMiddleware_EmptyCredentials_FailsClosed verifies the
// fail-closed contract with a nil/empty Credentials slice (as opposed to the
// single-empty-token case covered by TestAdminAuthMiddleware_EmptyConfigToken):
// every request is rejected with 401.
func TestAdminAuthMiddleware_EmptyCredentials_FailsClosed(t *testing.T) {
	spy := &spyHandler{}
	mw := AdminAuthMiddleware(AdminAuthConfig{})
	rec := httptest.NewRecorder()
	mw(spy).ServeHTTP(rec, bearerReq(http.MethodPost, "/admin/keys/rotate", "Bearer some-token"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (fail-closed when Credentials is empty)", rec.Code)
	}
	if spy.called {
		t.Fatal("inner handler must NOT be invoked when Credentials is empty (fail-closed)")
	}
}
