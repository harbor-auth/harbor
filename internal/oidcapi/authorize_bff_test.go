package oidcapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/bff"
	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/openapi"
	"github.com/harbor-auth/harbor/internal/oidc"
)

// testLoginURL is the login UI /authorize redirects unauthenticated browsers to
// when the BFF flow is enabled (mirrors LOGIN_URL in cmd/harbor-hot).
const testLoginURL = "https://mgmt.harbor.id/login"

// newBFFFlowServer builds a Server wired with a BFF session store and LoginURL,
// exactly as cmd/harbor-hot does when LOGIN_URL is configured. In this mode GET
// /authorize must NOT issue a code directly: it creates a BFF session and
// redirects the browser to the login UI so the passkey ceremony can run first.
// Returns the test server plus the session store so a test can assert a session
// was created.
func newBFFFlowServer(t *testing.T) (*httptest.Server, *bff.InMemoryBFFSessionStore) {
	t.Helper()
	clients := oidc.NewInMemoryClientRegistry()
	clients.Put(oidc.Client{
		ID:            testClientID,
		SectorID:      "localhost", // required for PPID derivation (§3.2)
		RedirectURIs:  []string{testRedirectURI},
		ScopesAllowed: []string{"openid", "profile", "email", "offline_access"},
	})
	signer, err := crypto.NewLocalSigner()
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	svc := oidc.NewService(oidc.ServiceConfig{
		Issuer:  "https://eu.harbor.id",
		Clients: clients,
		Codes:   oidc.NewInMemoryAuthCodeStore(),
		Tokens:  oidc.NewJWTIssuer(oidc.JWTIssuerConfig{Signer: signer}),
		// The stub resolver would issue a code in the legacy path; with the BFF
		// store wired below, /authorize must never reach it for an unauthenticated
		// request — it redirects to login instead.
		Sessions: oidc.NewStubSessionResolver("demo-subject-ppid"),
	})
	store := bff.NewInMemoryBFFSessionStore()
	srv := New(Config{
		Issuer:        "https://eu.harbor.id",
		Service:       svc,
		Signers:       []crypto.Signer{signer},
		BFFSessions:   store,
		LoginURL:      testLoginURL,
		BFFSessionTTL: 5 * time.Minute,
	})
	// The spec-generated router handles /authorize etc., but /authorize/complete
	// is a custom endpoint not in the OpenAPI spec — register it manually.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize/complete", srv.GetAuthorizeComplete)
	h := openapi.HandlerFromMux(srv, mux)
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts, store
}

// With the BFF flow enabled, GET /authorize for an unauthenticated browser must
// NOT issue a code. It creates a BFF session and 302-redirects to LoginURL with
// the request_id, so the passkey ceremony runs before any token is minted. This
// is the core of the auth-bypass fix (audit blocker 1.1): /authorize can no
// longer mint a code for whoever happens to call it.
//
// Task 4: also asserts that a browser nonce cookie is set and that the stored
// BrowserNonceHash matches its SHA-256, preventing session fixation
// (fix-bff-session-binding C3).
func TestAuthorize_BFFFlow_RedirectsToLogin(t *testing.T) {
	ts, store := newBFFFlowServer(t)

	res := getAuthorize(t, ts, validAuthorizeQuery())
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", res.StatusCode)
	}

	// The redirect target must be the login UI — NOT the RP's redirect_uri.
	vals := locationQuery(t, res, testLoginURL)

	// A request_id must be present so /login can look up the BFF session.
	requestID := vals.Get("request_id")
	if requestID == "" {
		t.Fatalf("redirect to login must carry a request_id, got %v", vals)
	}

	// Critically: no auth code may be issued for an unauthenticated request.
	if code := vals.Get("code"); code != "" {
		t.Fatalf("BFF /authorize must not issue a code before login: got code=%q", code)
	}

	// A BFF session must have been created under that request_id, carrying the
	// validated OIDC parameters and NO user (the passkey ceremony has not run).
	session, err := store.Get(context.Background(), requestID)
	if err != nil {
		t.Fatalf("expected a BFF session for request_id %q: %v", requestID, err)
	}
	if session.ClientID != testClientID {
		t.Fatalf("session ClientID = %q, want %q", session.ClientID, testClientID)
	}
	if session.RedirectURI != testRedirectURI {
		t.Fatalf("session RedirectURI = %q, want %q", session.RedirectURI, testRedirectURI)
	}
	if session.State != testState {
		t.Fatalf("session State = %q, want %q", session.State, testState)
	}
	if session.Scope != "openid profile" {
		t.Fatalf("session Scope = %q, want %q", session.Scope, "openid profile")
	}
	if session.UserID != "" {
		t.Fatalf("session UserID = %q, want empty (request is unauthenticated)", session.UserID)
	}

	// --- Nonce binding assertions (fix-bff-session-binding Task 4) ---
	//
	// A browser nonce cookie must be set so BeginLogin can prove the browser
	// that received the redirect is the same one that started /authorize.
	var nonceCookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == bff.NonceCookieName {
			nonceCookie = c
			break
		}
	}
	if nonceCookie == nil {
		t.Fatalf("missing %s cookie — nonce binding not established", bff.NonceCookieName)
	}

	// The cookie value must be a valid base64url-encoded 32-byte nonce.
	rawNonce, decErr := base64.RawURLEncoding.DecodeString(nonceCookie.Value)
	if decErr != nil {
		t.Fatalf("nonce cookie value is not valid base64url: %v", decErr)
	}
	if len(rawNonce) != 32 {
		t.Fatalf("nonce length = %d, want 32", len(rawNonce))
	}

	// The session must carry the SHA-256 hash of that nonce — not the raw value.
	if len(session.BrowserNonceHash) == 0 {
		t.Fatal("session.BrowserNonceHash is empty — hash was not stored")
	}
	expectedHash := bff.HashNonce(rawNonce)
	if !bytes.Equal(session.BrowserNonceHash, expectedHash) {
		t.Fatal("session.BrowserNonceHash does not match SHA-256 of cookie nonce")
	}

	// The nonce cookie must not appear in the response body (it is HttpOnly,
	// but we also assert it isn't echoed in any other form).
	if nonceCookie.HttpOnly != true {
		t.Error("nonce cookie must be HttpOnly")
	}
	if nonceCookie.Secure != true {
		t.Error("nonce cookie must be Secure")
	}
}

// A validation failure in the BFF flow must NOT redirect to the login UI and
// must NOT create a BFF session — a broken request never starts a ceremony.
// Here an unregistered client_id is a ChannelErrorPage failure (open-redirect
// defense, §11.7): 400 error page, no Location, no code.
func TestAuthorize_BFFFlow_InvalidRequest_ErrorPageNoRedirect(t *testing.T) {
	ts, _ := newBFFFlowServer(t)
	q := validAuthorizeQuery()
	q.Set("client_id", "nope-not-registered")

	res := getAuthorize(t, ts, q)
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "" {
		t.Fatalf("unexpected Location header %q — a rejected request must not redirect anywhere", loc)
	}
}

// /authorize/complete without an authenticated session must NOT issue a code.
// This is a critical security invariant (audit blocker 1.1): the endpoint only
// mints an authorization code when the BFF session carries a user_id set by the
// completed passkey ceremony. Attempting to call it before login, with a bad
// request_id, or with an expired session must all yield an error page — never a
// code that could be exchanged for tokens.
func TestAuthorizeComplete_NoSession_ErrorPageNoCode(t *testing.T) {
	ts, _ := newBFFFlowServer(t)

	// Call /authorize/complete with a made-up request_id that has no session.
	res, err := noRedirectClient().Get(ts.URL + "/authorize/complete?request_id=nonexistent-session-id")
	if err != nil {
		t.Fatalf("GET /authorize/complete: %v", err)
	}
	defer func() { _ = res.Body.Close() }()

	// Must be an error page, not a redirect with a code.
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (error page)", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "" {
		t.Fatalf("unexpected redirect %q — must not redirect when session is missing", loc)
	}
}

// /authorize/complete with an existing session but NO authenticated user
// (UserID still empty because the passkey ceremony hasn't completed) must
// also return an error page and never issue a code.
func TestAuthorizeComplete_SessionExistsButNoUser_ErrorPageNoCode(t *testing.T) {
	ts, store := newBFFFlowServer(t)

	// First, hit /authorize to create a BFF session (no login happens).
	res := getAuthorize(t, ts, validAuthorizeQuery())
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", res.StatusCode)
	}
	vals := locationQuery(t, res, testLoginURL)
	requestID := vals.Get("request_id")
	if requestID == "" {
		t.Fatalf("expected request_id in redirect")
	}

	// Verify the session exists but has no UserID.
	session, err := store.Get(context.Background(), requestID)
	if err != nil {
		t.Fatalf("session lookup: %v", err)
	}
	if session.UserID != "" {
		t.Fatalf("session.UserID = %q, want empty", session.UserID)
	}

	// Now call /authorize/complete with the real request_id AND the matching
	// browser nonce cookie (extracted from the /authorize response), but WITHOUT
	// having completed the passkey ceremony (UserID still empty). Seeding the
	// nonce ensures this test exercises the UserID gate, not the nonce gate.
	nonceCookie := nonceCookieFrom(t, res)
	completeRes := getAuthorizeCompleteWithCookie(t, ts, requestID, nonceCookie)
	defer func() { _ = completeRes.Body.Close() }()

	// Must be an error page — no code issued for unauthenticated session.
	if completeRes.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (error page)", completeRes.StatusCode)
	}
	if loc := completeRes.Header.Get("Location"); loc != "" {
		t.Fatalf("unexpected redirect %q — must not issue code for unauthenticated session", loc)
	}
}

// nonceCookieFrom extracts the browser nonce cookie set by a /authorize
// response so a follow-up request can present it at /authorize/complete.
func nonceCookieFrom(t *testing.T, res *http.Response) *http.Cookie {
	t.Helper()
	for _, c := range res.Cookies() {
		if c.Name == bff.NonceCookieName {
			return c
		}
	}
	t.Fatalf("missing %s cookie in /authorize response", bff.NonceCookieName)
	return nil
}

// getAuthorizeCompleteWithCookie issues GET /authorize/complete?request_id=<id>
// without following redirects, optionally attaching the given cookie (nil to
// omit it). Returns the raw response so the caller can inspect status/Location.
func getAuthorizeCompleteWithCookie(t *testing.T, ts *httptest.Server, requestID string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/authorize/complete?request_id="+requestID, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	res, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("GET /authorize/complete: %v", err)
	}
	return res
}

// seedAuthenticatedSession creates a BFF session directly in the store carrying
// a valid UserID and the SHA-256 hash of the returned raw nonce. This lets the
// nonce-gate tests target /authorize/complete with a session that would issue a
// code IF (and only if) the presented browser nonce matches — isolating the
// nonce check from the UserID check.
func seedAuthenticatedSession(t *testing.T, store *bff.InMemoryBFFSessionStore, requestID string) []byte {
	t.Helper()
	nonce, err := bff.NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce: %v", err)
	}
	record := bff.BFFSessionRecord{
		RequestID:        requestID,
		State:            testState,
		ClientID:         testClientID,
		RedirectURI:      testRedirectURI,
		Scope:            "openid profile",
		UserID:           "user-abc-123",
		BrowserNonceHash: bff.HashNonce(nonce),
		ExpiresAt:        time.Now().Add(5 * time.Minute),
	}
	if err := store.Create(context.Background(), record); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return nonce
}

// FIXATION / nonce-gate regression: an authenticated BFF session must NOT yield
// a code at /authorize/complete when the caller presents NO browser nonce
// cookie. Without the gate, an attacker who learned a request_id could complete
// the flow from a different browser. The response must be the no-redirect error
// page (no Location, no code).
func TestAuthorizeComplete_MissingNonce_ErrorPageNoCode(t *testing.T) {
	ts, store := newBFFFlowServer(t)
	const requestID = "seeded-request-id-missing-nonce"
	_ = seedAuthenticatedSession(t, store, requestID)

	// Call /authorize/complete with the real request_id but NO nonce cookie.
	res := getAuthorizeCompleteWithCookie(t, ts, requestID, nil)
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (error page)", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "" {
		t.Fatalf("unexpected redirect %q — must not issue a code without a matching browser nonce", loc)
	}
}

// FIXATION / nonce-gate regression: an authenticated BFF session must NOT yield
// a code at /authorize/complete when the caller presents the WRONG browser
// nonce cookie (a nonce whose hash does not match the stored one). This is the
// cross-browser takeover case: the attacker's browser holds its own nonce, not
// the victim's. The response must be the no-redirect error page.
func TestAuthorizeComplete_WrongNonce_ErrorPageNoCode(t *testing.T) {
	ts, store := newBFFFlowServer(t)
	const requestID = "seeded-request-id-wrong-nonce"
	_ = seedAuthenticatedSession(t, store, requestID)

	// Present a DIFFERENT (attacker-controlled) nonce whose hash cannot match.
	wrongNonce, err := bff.NewBrowserNonce()
	if err != nil {
		t.Fatalf("NewBrowserNonce: %v", err)
	}
	wrongCookie := &http.Cookie{
		Name:  bff.NonceCookieName,
		Value: base64.RawURLEncoding.EncodeToString(wrongNonce),
	}

	res := getAuthorizeCompleteWithCookie(t, ts, requestID, wrongCookie)
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (error page)", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "" {
		t.Fatalf("unexpected redirect %q — a mismatched browser nonce must never issue a code", loc)
	}
}

// /authorize/complete with no request_id query param must return an error page.
func TestAuthorizeComplete_MissingRequestID_ErrorPage(t *testing.T) {
	ts, _ := newBFFFlowServer(t)

	res, err := noRedirectClient().Get(ts.URL + "/authorize/complete")
	if err != nil {
		t.Fatalf("GET /authorize/complete: %v", err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "" {
		t.Fatalf("unexpected redirect %q — must not redirect without request_id", loc)
	}
}
