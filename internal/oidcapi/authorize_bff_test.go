package oidcapi

import (
	"context"
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
		Issuer:   "https://eu.harbor.id",
		Clients:  clients,
		Codes:    oidc.NewInMemoryAuthCodeStore(),
		Tokens:   oidc.NewJWTIssuer(oidc.JWTIssuerConfig{Signer: signer}),
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
	h := openapi.HandlerFromMux(srv, http.NewServeMux())
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts, store
}

// With the BFF flow enabled, GET /authorize for an unauthenticated browser must
// NOT issue a code. It creates a BFF session and 302-redirects to LoginURL with
// the request_id, so the passkey ceremony runs before any token is minted. This
// is the core of the auth-bypass fix (audit blocker 1.1): /authorize can no
// longer mint a code for whoever happens to call it.
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
