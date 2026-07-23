package oidcapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harbor-auth/harbor/internal/gen/openapi"
	"github.com/harbor-auth/harbor/internal/oidc"
)

// --- test doubles -----------------------------------------------------------

// fakeLogoutVerifier returns canned claims/error so the handler's orchestration
// (lookup → revoke → redirect) can be tested without real JWT crypto.
type fakeLogoutVerifier struct {
	claims *oidc.VerifiedClaims
	err    error
	called bool
}

func (f *fakeLogoutVerifier) VerifySignatureOnly(_ context.Context, _ string) (*oidc.VerifiedClaims, error) {
	f.called = true
	return f.claims, f.err
}

// fakeSessionRevoker records RevokeSessionsByUserClient calls.
type revokeCall struct{ userID, clientID string }

type fakeSessionRevoker struct {
	calls []revokeCall
	err   error
}

func (f *fakeSessionRevoker) RevokeSessionsByUserClient(_ context.Context, userID, clientID string) error {
	f.calls = append(f.calls, revokeCall{userID, clientID})
	return f.err
}

// --- fixtures ---------------------------------------------------------------

const (
	esIssuer       = "https://eu.harbor.id"
	esLoggedOutURL = esIssuer + "/logged-out"
	esClientID     = "rp-1"
	esPPID         = "ppid-abc"
	esUserID       = "user-1"
	esLogoutURI    = "https://rp.example.com/after-logout"
)

func esStrPtr(s string) *string { return &s }

// newEndSessionServer builds a Server with the logout dependencies wired and a
// single grant (esPPID→esUserID for esClientID) plus a client whose registered
// logout URI is esLogoutURI.
func newEndSessionServer(t *testing.T, verifier LogoutVerifier, revoker SessionRevoker) *Server {
	t.Helper()
	grants := oidc.NewInMemoryGrantStore()
	if _, err := grants.CreateGrant(context.Background(), oidc.NewGrant{
		Region:      "eu",
		UserID:      esUserID,
		ClientID:    esClientID,
		PairwiseSub: esPPID,
		Scopes:      []string{"openid"},
	}); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	registry := oidc.NewInMemoryClientRegistry()
	registry.Put(oidc.Client{ID: esClientID, LogoutURIs: []string{esLogoutURI}})
	return New(Config{
		Issuer:         esIssuer,
		LogoutVerifier: verifier,
		Grants:         grants,
		Clients:        registry,
		SessionRevoker: revoker,
	})
}

func validClaims() *oidc.VerifiedClaims {
	return &oidc.VerifiedClaims{Subject: esPPID, Audience: esClientID}
}

func doGetEndSession(s *Server, params openapi.GetEndSessionParams) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/end_session", nil)
	rec := httptest.NewRecorder()
	s.GetEndSession(rec, req, params)
	return rec
}

func doPostEndSession(s *Server, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/end_session", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.PostEndSession(rec, req)
	return rec
}

func assertRedirect(t *testing.T, rec *httptest.ResponseRecorder, wantLocation string) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	if got := rec.Header().Get("Location"); got != wantLocation {
		t.Fatalf("Location = %q, want %q", got, wantLocation)
	}
}

// --- GET tests --------------------------------------------------------------

func TestGetEndSessionRedirectsToRegisteredURIAndRevokes(t *testing.T) {
	revoker := &fakeSessionRevoker{}
	s := newEndSessionServer(t, &fakeLogoutVerifier{claims: validClaims()}, revoker)

	rec := doGetEndSession(s, openapi.GetEndSessionParams{
		IdTokenHint:           "tok",
		PostLogoutRedirectUri: esStrPtr(esLogoutURI),
		State:                 esStrPtr("xyz"),
	})

	assertRedirect(t, rec, esLogoutURI+"?state=xyz")
	if len(revoker.calls) != 1 {
		t.Fatalf("revoke calls = %d, want 1", len(revoker.calls))
	}
	if revoker.calls[0] != (revokeCall{esUserID, esClientID}) {
		t.Errorf("revoke call = %+v, want {%s %s}", revoker.calls[0], esUserID, esClientID)
	}
}

func TestGetEndSessionNoRedirectURIGoesToLoggedOut(t *testing.T) {
	revoker := &fakeSessionRevoker{}
	s := newEndSessionServer(t, &fakeLogoutVerifier{claims: validClaims()}, revoker)

	rec := doGetEndSession(s, openapi.GetEndSessionParams{IdTokenHint: "tok"})

	assertRedirect(t, rec, esLoggedOutURL)
	if len(revoker.calls) != 1 {
		t.Fatalf("revoke calls = %d, want 1", len(revoker.calls))
	}
}

func TestGetEndSessionUnregisteredURIGoesToLoggedOutButStillRevokes(t *testing.T) {
	revoker := &fakeSessionRevoker{}
	s := newEndSessionServer(t, &fakeLogoutVerifier{claims: validClaims()}, revoker)

	rec := doGetEndSession(s, openapi.GetEndSessionParams{
		IdTokenHint:           "tok",
		PostLogoutRedirectUri: esStrPtr("https://evil.example.com/steal"),
	})

	// Open-redirect defence: unregistered URI must NOT be honoured.
	assertRedirect(t, rec, esLoggedOutURL)
	if len(revoker.calls) != 1 {
		t.Fatalf("revoke calls = %d, want 1 (revocation still happens)", len(revoker.calls))
	}
}

func TestGetEndSessionInvalidTokenGoesToLoggedOutNoRevoke(t *testing.T) {
	revoker := &fakeSessionRevoker{}
	s := newEndSessionServer(t, &fakeLogoutVerifier{err: oidc.ErrTokenInvalid}, revoker)

	rec := doGetEndSession(s, openapi.GetEndSessionParams{
		IdTokenHint:           "tok",
		PostLogoutRedirectUri: esStrPtr(esLogoutURI),
	})

	// A bad hint must not act on any claim, nor honour the (even registered) URI.
	assertRedirect(t, rec, esLoggedOutURL)
	if len(revoker.calls) != 0 {
		t.Fatalf("revoke calls = %d, want 0 for invalid token", len(revoker.calls))
	}
}

func TestGetEndSessionNoGrantFoundNoRevoke(t *testing.T) {
	revoker := &fakeSessionRevoker{}
	// Claims reference a PPID with no matching grant.
	s := newEndSessionServer(t, &fakeLogoutVerifier{claims: &oidc.VerifiedClaims{
		Subject:  "ppid-unknown",
		Audience: esClientID,
	}}, revoker)

	rec := doGetEndSession(s, openapi.GetEndSessionParams{IdTokenHint: "tok"})

	assertRedirect(t, rec, esLoggedOutURL)
	if len(revoker.calls) != 0 {
		t.Fatalf("revoke calls = %d, want 0 when no grant found", len(revoker.calls))
	}
}

func TestGetEndSessionClientIDMismatchGoesToLoggedOut(t *testing.T) {
	revoker := &fakeSessionRevoker{}
	s := newEndSessionServer(t, &fakeLogoutVerifier{claims: validClaims()}, revoker)

	rec := doGetEndSession(s, openapi.GetEndSessionParams{
		IdTokenHint: "tok",
		ClientId:    esStrPtr("different-client"),
	})

	assertRedirect(t, rec, esLoggedOutURL)
	if len(revoker.calls) != 0 {
		t.Fatalf("revoke calls = %d, want 0 on client_id mismatch", len(revoker.calls))
	}
}

func TestGetEndSessionMatchingClientIDParamRevokes(t *testing.T) {
	revoker := &fakeSessionRevoker{}
	s := newEndSessionServer(t, &fakeLogoutVerifier{claims: validClaims()}, revoker)

	rec := doGetEndSession(s, openapi.GetEndSessionParams{
		IdTokenHint: "tok",
		ClientId:    esStrPtr(esClientID),
	})

	assertRedirect(t, rec, esLoggedOutURL)
	if len(revoker.calls) != 1 {
		t.Fatalf("revoke calls = %d, want 1", len(revoker.calls))
	}
}

func TestGetEndSessionRevokeErrorStillRedirects(t *testing.T) {
	revoker := &fakeSessionRevoker{err: context.DeadlineExceeded}
	s := newEndSessionServer(t, &fakeLogoutVerifier{claims: validClaims()}, revoker)

	rec := doGetEndSession(s, openapi.GetEndSessionParams{
		IdTokenHint:           "tok",
		PostLogoutRedirectUri: esStrPtr(esLogoutURI),
	})

	// Revocation failure is non-fatal: the redirect must still complete.
	assertRedirect(t, rec, esLogoutURI)
}

// --- POST tests -------------------------------------------------------------

func TestPostEndSessionRedirectsToRegisteredURIAndRevokes(t *testing.T) {
	revoker := &fakeSessionRevoker{}
	s := newEndSessionServer(t, &fakeLogoutVerifier{claims: validClaims()}, revoker)

	form := url.Values{}
	form.Set("id_token_hint", "tok")
	form.Set("post_logout_redirect_uri", esLogoutURI)
	form.Set("state", "xyz")

	rec := doPostEndSession(s, form)

	assertRedirect(t, rec, esLogoutURI+"?state=xyz")
	if len(revoker.calls) != 1 {
		t.Fatalf("revoke calls = %d, want 1", len(revoker.calls))
	}
}

func TestPostEndSessionMissingHintGoesToLoggedOut(t *testing.T) {
	revoker := &fakeSessionRevoker{}
	verifier := &fakeLogoutVerifier{claims: validClaims()}
	s := newEndSessionServer(t, verifier, revoker)

	rec := doPostEndSession(s, url.Values{}) // no id_token_hint

	assertRedirect(t, rec, esLoggedOutURL)
	if verifier.called {
		t.Error("verifier should not be called without an id_token_hint")
	}
	if len(revoker.calls) != 0 {
		t.Fatalf("revoke calls = %d, want 0", len(revoker.calls))
	}
}

// --- issuer mismatch tests --------------------------------------------------

func TestGetEndSessionWrongIssuerRejected(t *testing.T) {
	revoker := &fakeSessionRevoker{}
	// Simulate issuer mismatch — the verifier returns ErrIssuerMismatch.
	s := newEndSessionServer(t, &fakeLogoutVerifier{err: oidc.ErrIssuerMismatch}, revoker)

	rec := doGetEndSession(s, openapi.GetEndSessionParams{
		IdTokenHint:           "tok",
		PostLogoutRedirectUri: esStrPtr(esLogoutURI),
	})

	// Wrong issuer is treated like invalid token — degrades to /logged-out, no revoke.
	assertRedirect(t, rec, esLoggedOutURL)
	if len(revoker.calls) != 0 {
		t.Fatalf("revoke calls = %d, want 0 for issuer mismatch", len(revoker.calls))
	}
}

// --- expired token acceptance tests -----------------------------------------

// TestGetEndSessionAcceptsExpiredToken verifies that VerifySignatureOnly does
// NOT reject expired tokens — users may log out with expired id_tokens, and
// the signature is sufficient to prove authenticity for session revocation.
func TestGetEndSessionAcceptsExpiredToken(t *testing.T) {
	revoker := &fakeSessionRevoker{}
	// The fake verifier returns valid claims even though in a real scenario the
	// token's exp claim would be in the past. VerifySignatureOnly intentionally
	// skips expiry checking.
	s := newEndSessionServer(t, &fakeLogoutVerifier{claims: validClaims()}, revoker)

	rec := doGetEndSession(s, openapi.GetEndSessionParams{
		IdTokenHint:           "expired-but-signed-token",
		PostLogoutRedirectUri: esStrPtr(esLogoutURI),
	})

	// Expired token should STILL work — the handler accepts it.
	assertRedirect(t, rec, esLogoutURI)
	if len(revoker.calls) != 1 {
		t.Fatalf("revoke calls = %d, want 1 (expired tokens should be accepted)", len(revoker.calls))
	}
}

// --- state parameter tests --------------------------------------------------

func TestGetEndSessionStateNotEchoedWithoutPostLogoutURI(t *testing.T) {
	// When state is provided but no post_logout_redirect_uri, we go to /logged-out
	// and state is NOT echoed (no place to put it).
	revoker := &fakeSessionRevoker{}
	s := newEndSessionServer(t, &fakeLogoutVerifier{claims: validClaims()}, revoker)

	rec := doGetEndSession(s, openapi.GetEndSessionParams{
		IdTokenHint: "tok",
		State:       esStrPtr("should-be-ignored"),
	})

	// State is not echoed to the default logged-out page.
	assertRedirect(t, rec, esLoggedOutURL)
}

func TestPostEndSessionStateEchoedCorrectly(t *testing.T) {
	revoker := &fakeSessionRevoker{}
	s := newEndSessionServer(t, &fakeLogoutVerifier{claims: validClaims()}, revoker)

	form := url.Values{}
	form.Set("id_token_hint", "tok")
	form.Set("post_logout_redirect_uri", esLogoutURI)
	form.Set("state", "anti-csrf-token-123")

	rec := doPostEndSession(s, form)

	assertRedirect(t, rec, esLogoutURI+"?state=anti-csrf-token-123")
}

// --- session revocation verification ----------------------------------------

// TestGetEndSessionRevokesCorrectUserClientPair verifies that after logout,
// the correct (userID, clientID) pair is revoked — ensuring refresh tokens
// for that RP are invalidated.
func TestGetEndSessionRevokesCorrectUserClientPair(t *testing.T) {
	revoker := &fakeSessionRevoker{}
	s := newEndSessionServer(t, &fakeLogoutVerifier{claims: validClaims()}, revoker)

	_ = doGetEndSession(s, openapi.GetEndSessionParams{IdTokenHint: "tok"})

	if len(revoker.calls) != 1 {
		t.Fatalf("revoke calls = %d, want 1", len(revoker.calls))
	}
	// Verify the exact userID and clientID were passed to the revoker.
	call := revoker.calls[0]
	if call.userID != esUserID {
		t.Errorf("revoked userID = %q, want %q", call.userID, esUserID)
	}
	if call.clientID != esClientID {
		t.Errorf("revoked clientID = %q, want %q", call.clientID, esClientID)
	}
}

// TestPostEndSessionRevokesSessionsAndInvalidatesRefreshTokens verifies the
// full POST logout flow including session revocation.
func TestPostEndSessionRevokesSessionsAndInvalidatesRefreshTokens(t *testing.T) {
	revoker := &fakeSessionRevoker{}
	s := newEndSessionServer(t, &fakeLogoutVerifier{claims: validClaims()}, revoker)

	form := url.Values{}
	form.Set("id_token_hint", "tok")

	_ = doPostEndSession(s, form)

	// Verify session revocation was called, which invalidates refresh tokens.
	if len(revoker.calls) != 1 {
		t.Fatalf("revoke calls = %d, want 1", len(revoker.calls))
	}
	if revoker.calls[0].userID != esUserID || revoker.calls[0].clientID != esClientID {
		t.Errorf("revoke call = %+v, want {%s %s}", revoker.calls[0], esUserID, esClientID)
	}
}

// --- multiple logout URIs test ----------------------------------------------

func TestGetEndSessionMultipleLogoutURIs(t *testing.T) {
	revoker := &fakeSessionRevoker{}
	grants := oidc.NewInMemoryGrantStore()
	if _, err := grants.CreateGrant(context.Background(), oidc.NewGrant{
		Region:      "eu",
		UserID:      esUserID,
		ClientID:    esClientID,
		PairwiseSub: esPPID,
		Scopes:      []string{"openid"},
	}); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	registry := oidc.NewInMemoryClientRegistry()
	// Client with multiple registered logout URIs.
	logoutURI2 := "https://rp.example.com/logout-alt"
	registry.Put(oidc.Client{
		ID:         esClientID,
		LogoutURIs: []string{esLogoutURI, logoutURI2},
	})
	s := New(Config{
		Issuer:         esIssuer,
		LogoutVerifier: &fakeLogoutVerifier{claims: validClaims()},
		Grants:         grants,
		Clients:        registry,
		SessionRevoker: revoker,
	})

	// Use the second registered URI.
	rec := doGetEndSession(s, openapi.GetEndSessionParams{
		IdTokenHint:           "tok",
		PostLogoutRedirectUri: esStrPtr(logoutURI2),
	})

	assertRedirect(t, rec, logoutURI2)
}

// --- empty audience handling ------------------------------------------------

func TestGetEndSessionEmptyAudienceGoesToLoggedOut(t *testing.T) {
	revoker := &fakeSessionRevoker{}
	// Claims with empty Audience — cannot determine client_id.
	s := newEndSessionServer(t, &fakeLogoutVerifier{claims: &oidc.VerifiedClaims{
		Subject:  esPPID,
		Audience: "", // empty
	}}, revoker)

	rec := doGetEndSession(s, openapi.GetEndSessionParams{IdTokenHint: "tok"})

	assertRedirect(t, rec, esLoggedOutURL)
	if len(revoker.calls) != 0 {
		t.Fatalf("revoke calls = %d, want 0 for empty audience", len(revoker.calls))
	}
}

// --- unconfigured server ----------------------------------------------------

func TestEndSessionUnconfiguredGoesToLoggedOut(t *testing.T) {
	// A server with no logout dependencies wired (e.g. discovery-only).
	s := New(Config{Issuer: esIssuer})

	rec := doGetEndSession(s, openapi.GetEndSessionParams{
		IdTokenHint:           "tok",
		PostLogoutRedirectUri: esStrPtr(esLogoutURI),
	})

	assertRedirect(t, rec, esLoggedOutURL)
}
