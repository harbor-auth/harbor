package mgmtapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harbor-auth/harbor/internal/oidc"
)

// =============================================================================
// Negative Spoofing Tests — X-Harbor-User-ID Header Must Never Grant Access
// =============================================================================
//
// These tests are the security gate for audit finding C1: the header-spoofing
// vulnerability. Every user-scoped endpoint must resolve the caller from the
// BFF session context (via CallerSource), never from a client-supplied header.

// userScopedEndpoints is a table of representative user-scoped endpoints
// that all require an authenticated caller. Each entry is (method, path).
// POST /enroll, POST /recovery/begin, POST /recovery/complete are intentionally
// absent: they are the legitimate unauthenticated paths.
var userScopedEndpoints = []struct {
	method string
	path   string
}{
	{"GET", "/consent-grants"},
	{"DELETE", "/consent-grants/some-client"},
	{"GET", "/audit-events"},
	{"GET", "/relay-addresses"},
	{"DELETE", "/relay-addresses/some-token"},
	{"POST", "/byo-domains"},
	{"GET", "/byo-domains"},
	{"POST", "/mfa/enroll"},
	{"POST", "/mfa/activate"},
	{"POST", "/mfa/verify"},
	{"POST", "/mfa/verify-recovery"},
	{"GET", "/mfa/factors"},
	{"DELETE", "/mfa/factors/factor-1"},
	{"POST", "/recovery/codes"},
	{"GET", "/recovery/factors"},
	{"POST", "/compliance/export"},
	{"POST", "/compliance/erase"},
}

// newMinimalServer returns a Server with the given CallerSource and no stores
// wired (all nil). The callerID check fires before any nil-store check on
// every user-scoped endpoint, so nil stores do not mask a missing 401.
func newMinimalServer(callerSource CallerSource) *Server {
	s := newTestServer(nil)
	if callerSource != nil {
		s = s.WithCallerSource(callerSource)
	}
	return s
}

// TestSpoofing_HeaderPresent_NoSession verifies that a request carrying the
// X-Harbor-User-ID header but no valid BFF session (CallerSource returns "")
// is rejected with 401 on every user-scoped endpoint.
//
// NEGATIVE test 1: spoofed header + no session → 401 everywhere.
func TestSpoofing_HeaderPresent_NoSession(t *testing.T) {
	for _, ep := range userScopedEndpoints {
		ep := ep
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			// fakeCallerSource with empty userID simulates no authenticated session.
			srv := newMinimalServer(fakeCallerSource{userID: ""})
			mux := http.NewServeMux()
			srv.Routes(mux)

			req := httptest.NewRequest(ep.method, ep.path, nil)
			// Attacker injects the header hoping it will be read.
			req.Header.Set("X-Harbor-User-ID", "victim-user")
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("SECURITY: status = %d, want 401; X-Harbor-User-ID header must never grant access without a BFF session", rec.Code)
			}
		})
	}
}

// TestSpoofing_HeaderPresentWithWrongUser_StoreReceivesSessionUser is the
// definitive cross-user isolation test. It verifies that when the BFF session
// belongs to user-A but the request also carries X-Harbor-User-ID: user-B,
// the business layer receives user-A (the session identity) and user-B (the
// spoofed header) is silently ignored.
//
// NEGATIVE test 2: session=user-A + spoofed header=user-B → user-A wins.
func TestSpoofing_HeaderPresentWithWrongUser_StoreReceivesSessionUser(t *testing.T) {
	const sessionUser = "user-A"
	const spoofedUser = "user-B"

	recorder := &recordingConsentStore{}
	srv := newTestServer(nil).
		WithCallerSource(fakeCallerSource{userID: sessionUser}).
		WithConsentStore(recorder)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("GET", "/consent-grants", nil)
	req.Header.Set("X-Harbor-User-ID", spoofedUser) // spoofed — must be ignored
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (valid session should succeed)", rec.Code)
	}

	// SECURITY: the store must have received user-A (session), never user-B (header).
	if recorder.lastListUserID != sessionUser {
		t.Errorf("SECURITY: store received userID = %q, want %q (session user); spoofed header %q must be ignored",
			recorder.lastListUserID, sessionUser, spoofedUser)
	}
	if recorder.lastListUserID == spoofedUser {
		t.Errorf("SECURITY: spoofed X-Harbor-User-ID %q reached the store — cross-user takeover", spoofedUser)
	}
}

// recordingConsentStore is a ConsentStore that records the userID it receives
// from List so tests can assert which identity reached the business layer.
type recordingConsentStore struct {
	lastListUserID string
}

func (r *recordingConsentStore) FindGrant(_ context.Context, _, _ string) (oidc.Grant, bool, error) {
	return oidc.Grant{}, false, nil
}

func (r *recordingConsentStore) ListGrantsByUser(_ context.Context, userID string) ([]oidc.Grant, error) {
	r.lastListUserID = userID
	return nil, nil
}

func (r *recordingConsentStore) RevokeGrantAndSessions(_ context.Context, _ string) (bool, error) {
	return false, nil
}
