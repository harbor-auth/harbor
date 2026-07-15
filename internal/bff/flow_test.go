// BFF flow integration tests.
//
// Unlike the per-handler unit tests (session_test.go, login_test.go,
// middleware_test.go, and oidcapi/authorize_test.go), this file wires the
// REAL /authorize + /authorize/complete handlers (internal/oidcapi) together
// with the REAL /login + /login/complete handlers (internal/bff) against a
// single shared bff.BFFSessionStore, and drives the four-stage ceremony
// end-to-end:
//
//  1. GET  /authorize          → creates a BFF session, 302 → /login?request_id=…
//  2. GET  /login              → reads the session, sets the __Host-harbor-bff cookie
//  3. POST /login/complete     → validates the cookie, writes user_id, 302 → /authorize/complete
//  4. GET  /authorize/complete → reads the authenticated user_id, issues a code, 302 → RP
//
// This catches the "each unit is green but the assembled flow is broken" class
// of bug — e.g. a request_id or cookie name mismatch between the two packages,
// or a session field that /authorize populates but /authorize/complete never
// reads.
//
// The file is in the external test package (bff_test) so it can import
// internal/oidcapi, which imports internal/bff — a dependency that would be a
// cycle for an in-package (package bff) test. Go compiles external test
// packages last, which breaks the cycle.
//
// Cookie propagation is done manually between httptest recorders (rather than
// via a cookie jar over a live server) because the BFF cookie uses the __Host-
// prefix with Secure=true, which a jar refuses to send over httptest's plain
// HTTP. The /login/complete step calls FinishLoginWithParsedData with a mock
// WebAuthnService for the same reason login_test.go does: constructing a valid
// signed WebAuthn assertion body is out of scope for a flow-wiring test.
package bff_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/harbor/harbor/internal/bff"
	"github.com/harbor/harbor/internal/gen/openapi"
	"github.com/harbor/harbor/internal/oidc"
	"github.com/harbor/harbor/internal/oidcapi"
)

const (
	itClientID    = "demo-client"
	itRedirectURI = "http://localhost:3000/callback"
	itState       = "state-int-xyz"
	itLoginPath   = "/login"
	itUserID      = "authenticated-user-42"
	// RFC 7636 Appendix B known-answer challenge (matches its verifier); we only
	// need a well-formed S256 challenge to pass /authorize validation — the code
	// is never exchanged in these tests.
	itPKCEChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// mockWebAuthn implements bff.WebAuthnService, returning a fixed user id from
// FinishLogin so the flow can complete without a real assertion ceremony.
type mockWebAuthn struct{ userID string }

func (m *mockWebAuthn) BeginLogin(_ context.Context, _ []byte) (*protocol.CredentialAssertion, string, error) {
	return &protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge: []byte("integration-challenge"),
		},
	}, "webauthn-session-key", nil
}

func (m *mockWebAuthn) FinishLogin(_ context.Context, _ string, _ *protocol.ParsedCredentialAssertionData) (string, error) {
	return m.userID, nil
}

// mockResolver implements bff.UserResolver with a fixed user handle.
type mockResolver struct{}

func (m *mockResolver) ResolveUser(_ context.Context, _ *http.Request, _ bff.BFFSessionRecord) ([]byte, error) {
	return []byte("user-handle"), nil
}

// newBFFIntegrationEnv wires an oidcapi.Server (BFF mode, LoginURL=/login) and a
// bff.LoginHandler against ONE shared in-memory BFF session store — exactly the
// composition cmd/harbor-mgmt performs — and returns all three so a test can
// drive the ceremony and inspect the store.
//
// NOTE: The /authorize/complete endpoint is NOT part of the generated OpenAPI
// spec (ServerInterface) — it's a BFF-specific route that is manually registered
// in production (cmd/harbor-mgmt). We replicate that wiring here by adding the
// route to the mux before passing it to HandlerFromMux.
func newBFFIntegrationEnv(t *testing.T) (http.Handler, *bff.LoginHandler, *bff.InMemoryBFFSessionStore) {
	t.Helper()

	clients := oidc.NewInMemoryClientRegistry()
	clients.Put(oidc.Client{
		ID:            itClientID,
		SectorID:      "localhost", // required for PPID derivation (§3.2)
		RedirectURIs:  []string{itRedirectURI},
		ScopesAllowed: []string{"openid", "profile", "email", "offline_access"},
	})
	svc := oidc.NewService(oidc.ServiceConfig{
		Issuer:   "https://eu.harbor.id",
		Clients:  clients,
		Codes:    oidc.NewInMemoryAuthCodeStore(),
		Tokens:   oidc.NewPlaceholderIssuer(),
		Sessions: oidc.NewStubSessionResolver("demo-subject-ppid"),
	})

	store := bff.NewInMemoryBFFSessionStore()
	srv := oidcapi.New(oidcapi.Config{
		Issuer:      "https://eu.harbor.id",
		Service:     svc,
		BFFSessions: store,
		LoginURL:    itLoginPath,
	})

	// Create a mux and manually register /authorize/complete (not in OpenAPI spec).
	// This mirrors the production wiring in cmd/harbor-mgmt.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize/complete", srv.GetAuthorizeComplete)

	// Now let the generated code register the spec-defined routes on the same mux.
	oidcHandler := openapi.HandlerFromMux(srv, mux)

	loginHandler := bff.NewLoginHandler(store, &mockWebAuthn{userID: itUserID}, &mockResolver{})
	return oidcHandler, loginHandler, store
}

// validITAuthorizeQuery returns a query that passes every /authorize check.
func validITAuthorizeQuery() url.Values {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", itClientID)
	q.Set("redirect_uri", itRedirectURI)
	q.Set("scope", "openid profile")
	q.Set("state", itState)
	q.Set("nonce", "n-int-9f2c")
	q.Set("code_challenge", itPKCEChallenge)
	q.Set("code_challenge_method", "S256")
	return q
}

// locationOf parses the Location header of a redirect recorder.
func locationOf(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatalf("missing Location header (status %d)", rec.Code)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location %q: %v", loc, err)
	}
	return u
}

// TestBFFFlow_FullHappyPath drives all four ceremony stages in sequence,
// asserting the invariant at each hand-off: session created → cookie set →
// user_id written → code issued + session consumed + cookie cleared.
func TestBFFFlow_FullHappyPath(t *testing.T) {
	oidcHandler, loginHandler, store := newBFFIntegrationEnv(t)
	ctx := context.Background()

	// --- Stage 1: GET /authorize creates a BFF session and redirects to /login ---
	authReq := httptest.NewRequest(http.MethodGet, "/authorize?"+validITAuthorizeQuery().Encode(), nil)
	authRec := httptest.NewRecorder()
	oidcHandler.ServeHTTP(authRec, authReq)

	if authRec.Code != http.StatusFound {
		t.Fatalf("/authorize status = %d, want 302", authRec.Code)
	}
	loginLoc := locationOf(t, authRec)
	if loginLoc.Path != itLoginPath {
		t.Fatalf("/authorize redirected to path %q, want %q", loginLoc.Path, itLoginPath)
	}
	requestID := loginLoc.Query().Get("request_id")
	if requestID == "" {
		t.Fatal("/authorize redirect missing request_id")
	}
	sess, err := store.Get(ctx, requestID)
	if err != nil {
		t.Fatalf("session not created by /authorize: %v", err)
	}
	if sess.ClientID != itClientID || sess.RedirectURI != itRedirectURI || sess.State != itState {
		t.Fatalf("session fields mismatch after /authorize: %+v", sess)
	}
	if sess.UserID != "" {
		t.Fatalf("session.UserID = %q, want empty before login", sess.UserID)
	}

	// --- Stage 2: GET /login reads the session and sets the BFF cookie ---
	loginReq := httptest.NewRequest(http.MethodGet, itLoginPath+"?request_id="+requestID, nil)
	loginRec := httptest.NewRecorder()
	loginHandler.BeginLogin(loginRec, loginReq)

	if loginRec.Code != http.StatusOK {
		t.Fatalf("/login status = %d, want 200", loginRec.Code)
	}
	loginCookies := loginRec.Result().Cookies()
	var bffCookie *http.Cookie
	for _, c := range loginCookies {
		if c.Name == bff.CookieName {
			bffCookie = c
		}
	}
	if bffCookie == nil {
		t.Fatal("/login did not set the BFF session cookie")
	}
	if bffCookie.Value != requestID {
		t.Fatalf("BFF cookie value = %q, want %q (must bind to the same request_id)", bffCookie.Value, requestID)
	}

	// --- Stage 3: POST /login/complete validates the cookie and writes user_id ---
	completeReq := httptest.NewRequest(http.MethodPost, itLoginPath+"/complete", nil)
	for _, c := range loginCookies {
		completeReq.AddCookie(c)
	}
	completeRec := httptest.NewRecorder()
	loginHandler.FinishLoginWithParsedData(completeRec, completeReq, &protocol.ParsedCredentialAssertionData{})

	if completeRec.Code != http.StatusFound {
		t.Fatalf("/login/complete status = %d, want 302", completeRec.Code)
	}
	completeLoc := locationOf(t, completeRec)
	if completeLoc.Path != "/authorize/complete" {
		t.Fatalf("/login/complete redirected to %q, want /authorize/complete", completeLoc.Path)
	}
	if got := completeLoc.Query().Get("request_id"); got != requestID {
		t.Fatalf("/login/complete request_id = %q, want %q", got, requestID)
	}
	sess, err = store.Get(ctx, requestID)
	if err != nil {
		t.Fatalf("session missing after /login/complete: %v", err)
	}
	if sess.UserID != itUserID {
		t.Fatalf("session.UserID = %q, want %q after passkey auth", sess.UserID, itUserID)
	}

	// --- Stage 4: GET /authorize/complete reads user_id and issues a code ---
	resumeReq := httptest.NewRequest(http.MethodGet, "/authorize/complete?request_id="+requestID, nil)
	resumeReq.AddCookie(&http.Cookie{Name: bff.CookieName, Value: requestID})
	resumeRec := httptest.NewRecorder()
	oidcHandler.ServeHTTP(resumeRec, resumeReq)

	if resumeRec.Code != http.StatusFound {
		t.Fatalf("/authorize/complete status = %d, want 302", resumeRec.Code)
	}
	rpLoc := locationOf(t, resumeRec)
	rpBase := rpLoc.Scheme + "://" + rpLoc.Host + rpLoc.Path
	if rpBase != itRedirectURI {
		t.Fatalf("/authorize/complete redirected to %q, want %q", rpBase, itRedirectURI)
	}
	if code := rpLoc.Query().Get("code"); code == "" {
		t.Fatal("/authorize/complete redirect missing code")
	}
	if got := rpLoc.Query().Get("state"); got != itState {
		t.Fatalf("state = %q, want %q (must be echoed to the RP)", got, itState)
	}
	// Session must be deleted (one-time use).
	if _, err := store.Get(ctx, requestID); err == nil {
		t.Fatal("session must be deleted after /authorize/complete (one-time use)")
	}
	// BFF cookie must be cleared.
	var cleared bool
	for _, c := range resumeRec.Result().Cookies() {
		if c.Name == bff.CookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("/authorize/complete must clear the BFF cookie (MaxAge<0)")
	}
}

// TestBFFFlow_AuthorizeCompleteBeforeLogin_ErrorPage verifies that resuming the
// flow before the passkey ceremony has set a user_id renders an error page —
// never issues a code — and leaves the session intact (not consumed).
func TestBFFFlow_AuthorizeCompleteBeforeLogin_ErrorPage(t *testing.T) {
	oidcHandler, _, store := newBFFIntegrationEnv(t)
	ctx := context.Background()

	authReq := httptest.NewRequest(http.MethodGet, "/authorize?"+validITAuthorizeQuery().Encode(), nil)
	authRec := httptest.NewRecorder()
	oidcHandler.ServeHTTP(authRec, authReq)
	requestID := locationOf(t, authRec).Query().Get("request_id")
	if requestID == "" {
		t.Fatal("no request_id from /authorize")
	}

	// Resume without ever authenticating.
	resumeReq := httptest.NewRequest(http.MethodGet, "/authorize/complete?request_id="+requestID, nil)
	resumeReq.AddCookie(&http.Cookie{Name: bff.CookieName, Value: requestID})
	resumeRec := httptest.NewRecorder()
	oidcHandler.ServeHTTP(resumeRec, resumeReq)

	if resumeRec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resumeRec.Code)
	}
	if loc := resumeRec.Header().Get("Location"); loc != "" {
		t.Fatalf("unexpected Location %q — an unauthenticated resume must not redirect", loc)
	}
	// Session must be preserved on the error path (not consumed).
	if _, err := store.Get(ctx, requestID); err != nil {
		t.Fatalf("session should be preserved on error, got: %v", err)
	}
}

// TestBFFFlow_AuthorizeCompleteUnknownRequestID_ErrorPage verifies that an
// unknown/forged request_id at /authorize/complete renders an error page with
// no redirect (open-redirect defense, docs/DESIGN.md §11.7).
func TestBFFFlow_AuthorizeCompleteUnknownRequestID_ErrorPage(t *testing.T) {
	oidcHandler, _, _ := newBFFIntegrationEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/authorize/complete?request_id=does-not-exist", nil)
	rec := httptest.NewRecorder()
	oidcHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("unexpected Location %q — an unknown session must not redirect", loc)
	}
}
