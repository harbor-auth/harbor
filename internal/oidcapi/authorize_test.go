package oidcapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harbor/harbor/internal/gen/openapi"
	"github.com/harbor/harbor/internal/oidc"
)

// RFC 7636 Appendix B known-answer vector, reused across the HTTP flow tests.
const (
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

const (
	testClientID    = "demo-client"
	testRedirectURI = "http://localhost:3000/callback"
	testState       = "xyz789"
)

// newFlowServer builds a Server wired to a real oidc.Service with in-memory
// stores + a seeded demo client, then serves it through the spec-generated
// router — exactly the wiring cmd/harbor-hot performs.
func newFlowServer(t *testing.T) *httptest.Server {
	t.Helper()
	clients := oidc.NewInMemoryClientRegistry()
	clients.Put(oidc.Client{
		ID:            testClientID,
		RedirectURIs:  []string{testRedirectURI},
		ScopesAllowed: []string{"openid", "profile", "email", "offline_access"},
	})
	svc := oidc.NewService(oidc.ServiceConfig{
		Issuer:   "https://eu.harbor.id",
		Clients:  clients,
		Codes:    oidc.NewInMemoryAuthCodeStore(),
		Tokens:   oidc.NewPlaceholderIssuer(),
		Sessions: oidc.NewStubSessionResolver("demo-subject-ppid"),
	})
	srv := New(Config{Issuer: "https://eu.harbor.id", Service: svc})
	h := openapi.HandlerFromMux(srv, http.NewServeMux())
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

// noRedirectClient returns an http.Client that never follows redirects, so a 302
// response (and its Location header) can be inspected directly.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// validAuthorizeQuery returns a query that passes every /authorize check, so a
// test can mutate exactly one parameter to isolate a single failure.
func validAuthorizeQuery() url.Values {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", testClientID)
	q.Set("redirect_uri", testRedirectURI)
	q.Set("scope", "openid profile")
	q.Set("state", testState)
	q.Set("nonce", "n-9f2c")
	q.Set("code_challenge", pkceChallenge)
	q.Set("code_challenge_method", "S256")
	return q
}

// getAuthorize issues GET /authorize?<query> without following redirects.
func getAuthorize(t *testing.T, ts *httptest.Server, q url.Values) *http.Response {
	t.Helper()
	res, err := noRedirectClient().Get(ts.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	return res
}

// locationQuery parses the Location header of a redirect response and returns
// its query parameters, asserting the base (scheme://host/path) matches want.
func locationQuery(t *testing.T, res *http.Response, wantBase string) url.Values {
	t.Helper()
	loc := res.Header.Get("Location")
	if loc == "" {
		t.Fatalf("missing Location header on %d response", res.StatusCode)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location %q: %v", loc, err)
	}
	gotBase := u.Scheme + "://" + u.Host + u.Path
	if gotBase != wantBase {
		t.Fatalf("redirect base = %q, want %q", gotBase, wantBase)
	}
	return u.Query()
}

// Open-redirect defense: an unknown client_id must render an error page and MUST
// NOT set a Location header (docs/DESIGN.md §11.7).
func TestAuthorize_UnknownClient_ErrorPageNoRedirect(t *testing.T) {
	ts := newFlowServer(t)
	q := validAuthorizeQuery()
	q.Set("client_id", "nope-not-registered")

	res := getAuthorize(t, ts, q)
	defer res.Body.Close()

	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "" {
		t.Fatalf("unexpected Location header %q — must not redirect an unproven target", loc)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type = %q, want text/html", ct)
	}
}

// Open-redirect defense: a redirect_uri that isn't an exact registered match
// must also render an error page with no Location.
func TestAuthorize_RedirectMismatch_ErrorPageNoRedirect(t *testing.T) {
	ts := newFlowServer(t)
	q := validAuthorizeQuery()
	q.Set("redirect_uri", "http://evil.example/callback")

	res := getAuthorize(t, ts, q)
	defer res.Body.Close()

	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "" {
		t.Fatalf("unexpected Location header %q — must not redirect to a non-registered URI", loc)
	}
}

// A redirect-channel error (missing openid scope) redirects back to the
// registered redirect_uri with error + echoed state.
func TestAuthorize_MissingOpenIDScope_RedirectsWithError(t *testing.T) {
	ts := newFlowServer(t)
	q := validAuthorizeQuery()
	q.Set("scope", "profile")

	res := getAuthorize(t, ts, q)
	defer res.Body.Close()

	if res.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", res.StatusCode)
	}
	vals := locationQuery(t, res, testRedirectURI)
	if got := vals.Get("error"); got != "invalid_scope" {
		t.Fatalf("error = %q, want invalid_scope", got)
	}
	if got := vals.Get("state"); got != testState {
		t.Fatalf("state = %q, want %q (must be echoed)", got, testState)
	}
	if vals.Get("code") != "" {
		t.Fatalf("error redirect must not carry a code")
	}
}

// unsupported response_type is a redirect-channel error too.
func TestAuthorize_UnsupportedResponseType_RedirectsWithError(t *testing.T) {
	ts := newFlowServer(t)
	q := validAuthorizeQuery()
	q.Set("response_type", "token")

	res := getAuthorize(t, ts, q)
	defer res.Body.Close()

	if res.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", res.StatusCode)
	}
	vals := locationQuery(t, res, testRedirectURI)
	if got := vals.Get("error"); got != "unsupported_response_type" {
		t.Fatalf("error = %q, want unsupported_response_type", got)
	}
	if got := vals.Get("state"); got != testState {
		t.Fatalf("state = %q, want %q (must be echoed)", got, testState)
	}
}

// Happy path: a valid request redirects back with a non-empty code + state.
func TestAuthorize_HappyPath_RedirectsWithCode(t *testing.T) {
	ts := newFlowServer(t)

	res := getAuthorize(t, ts, validAuthorizeQuery())
	defer res.Body.Close()

	if res.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", res.StatusCode)
	}
	vals := locationQuery(t, res, testRedirectURI)
	if vals.Get("code") == "" {
		t.Fatalf("expected a non-empty code in the redirect")
	}
	if got := vals.Get("state"); got != testState {
		t.Fatalf("state = %q, want %q", got, testState)
	}
	if vals.Get("error") != "" {
		t.Fatalf("unexpected error on happy path: %q", vals.Get("error"))
	}
}
