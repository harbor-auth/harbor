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
