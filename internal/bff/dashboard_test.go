package bff

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/oidc"
	"github.com/harbor-auth/harbor/web"
)

// --- fake store implementations ---

type fakeDashConsentStore struct {
	listCalledWith   []string
	grants           map[string][]oidc.ConsentGrant
	revokeCalledWith []string
}

func (f *fakeDashConsentStore) List(_ context.Context, userID string) ([]oidc.ConsentGrant, error) {
	f.listCalledWith = append(f.listCalledWith, userID)
	return f.grants[userID], nil
}

func (f *fakeDashConsentStore) Get(_ context.Context, _, _ string) (oidc.ConsentGrant, bool, error) {
	return oidc.ConsentGrant{}, false, nil
}

func (f *fakeDashConsentStore) Revoke(_ context.Context, id string) error {
	f.revokeCalledWith = append(f.revokeCalledWith, id)
	return nil
}

type fakeDashSessionStore struct {
	listCalledWith        []string
	sessions              map[string][]oidc.RefreshSession
	revokeSessionCalls    []string
	revokeUserClientCalls []struct{ userID, clientID string }
}

func (f *fakeDashSessionStore) ListSessionsByUser(_ context.Context, userID string) ([]oidc.RefreshSession, error) {
	f.listCalledWith = append(f.listCalledWith, userID)
	return f.sessions[userID], nil
}

func (f *fakeDashSessionStore) RevokeSession(_ context.Context, id string) error {
	f.revokeSessionCalls = append(f.revokeSessionCalls, id)
	return nil
}

func (f *fakeDashSessionStore) RevokeSessionsByUserClient(_ context.Context, userID, clientID string) error {
	f.revokeUserClientCalls = append(f.revokeUserClientCalls, struct{ userID, clientID string }{userID, clientID})
	return nil
}

type fakeDashCredStore struct {
	listCalledWith []string
	creds          map[string][]clients.DashboardCredential
}

func (f *fakeDashCredStore) ListCredentialsByUser(_ context.Context, userID string) ([]clients.DashboardCredential, error) {
	f.listCalledWith = append(f.listCalledWith, userID)
	return f.creds[userID], nil
}

func (f *fakeDashCredStore) DeleteCredential(_ context.Context, _, _ string) error {
	return nil
}

// --- helpers ---

func newTestDashHandler(t *testing.T, consents DashboardConsentStore, sessions DashboardSessionStore, creds clients.DashboardCredentialStore, relay DashboardRelayStore) *DashboardHandler {
	t.Helper()
	tmpl, err := web.ParseDashboardTemplates()
	if err != nil {
		t.Fatalf("ParseDashboardTemplates: %v", err)
	}
	return NewDashboardHandler(consents, sessions, creds, nil, relay, tmpl, nil)
}

func authedCtxRequest(method, path, userID string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	return r.WithContext(ContextWithUserID(r.Context(), userID))
}

// --- tests ---

// TestDashboard_OwnDataOnly verifies that GetConnectedApps calls the consent
// store with the authenticated caller's user ID only, and that the response
// contains user A's data but never user B's data.
func TestDashboard_OwnDataOnly(t *testing.T) {
	consentStore := &fakeDashConsentStore{
		grants: map[string][]oidc.ConsentGrant{
			"user-a": {{ID: "grant-a", UserID: "user-a", ClientID: "app-a", GrantedAt: time.Now()}},
			"user-b": {{ID: "grant-b", UserID: "user-b", ClientID: "app-b", GrantedAt: time.Now()}},
		},
	}
	sessionStore := &fakeDashSessionStore{sessions: map[string][]oidc.RefreshSession{}}
	credStore := &fakeDashCredStore{creds: map[string][]clients.DashboardCredential{}}
	h := newTestDashHandler(t, consentStore, sessionStore, credStore, nil)

	rec := httptest.NewRecorder()
	r := authedCtxRequest(http.MethodGet, "/dashboard/apps", "user-a")
	h.GetConnectedApps(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	// Store was called exactly once with user-a's ID.
	if len(consentStore.listCalledWith) != 1 || consentStore.listCalledWith[0] != "user-a" {
		t.Errorf("consent.List called with %v, want [user-a]", consentStore.listCalledWith)
	}

	body := rec.Body.String()
	// user-b's data must not appear in user-a's response.
	if strings.Contains(body, "app-b") {
		t.Error("cross-user data leak: user-b's app appeared in user-a's response")
	}
	// user-a's data must appear.
	if !strings.Contains(body, "app-a") {
		t.Error("user-a's app missing from response")
	}
}

// TestDashboard_RevokeCascade verifies that PostRevokeApp calls both
// DashboardConsentStore.Revoke and DashboardSessionStore.RevokeSessionsByUserClient
// for the correct (user, client) pair — the cascade must not be skipped.
func TestDashboard_RevokeCascade(t *testing.T) {
	const grantID = "grant-xyz"
	const clientID = "rp-xyz"

	consentStore := &fakeDashConsentStore{
		grants: map[string][]oidc.ConsentGrant{
			"user-a": {{ID: grantID, UserID: "user-a", ClientID: clientID}},
		},
	}
	sessionStore := &fakeDashSessionStore{sessions: map[string][]oidc.RefreshSession{}}
	credStore := &fakeDashCredStore{}
	h := newTestDashHandler(t, consentStore, sessionStore, credStore, nil)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/dashboard/apps/"+grantID+"/revoke", nil)
	r.SetPathValue("grant_id", grantID)
	r = r.WithContext(ContextWithUserID(r.Context(), "user-a"))

	h.PostRevokeApp(rec, r)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 SeeOther", rec.Code)
	}

	// Consent grant was revoked.
	if len(consentStore.revokeCalledWith) != 1 || consentStore.revokeCalledWith[0] != grantID {
		t.Errorf("Revoke called with %v, want [%s]", consentStore.revokeCalledWith, grantID)
	}

	// Session cascade fired exactly once with the correct (user, client).
	if len(sessionStore.revokeUserClientCalls) != 1 {
		t.Fatalf("RevokeSessionsByUserClient called %d times, want 1", len(sessionStore.revokeUserClientCalls))
	}
	call := sessionStore.revokeUserClientCalls[0]
	if call.userID != "user-a" {
		t.Errorf("cascade userID = %q, want user-a", call.userID)
	}
	if call.clientID != clientID {
		t.Errorf("cascade clientID = %q, want %s", call.clientID, clientID)
	}
}

// TestDashboard_RelayAbsentGraceful verifies that GetRelayToggles returns 200
// and renders the "relay not available" view rather than a 503 error when the
// relay store is nil (soft dependency — INVARIANT §4).
func TestDashboard_RelayAbsentGraceful(t *testing.T) {
	consentStore := &fakeDashConsentStore{grants: map[string][]oidc.ConsentGrant{}}
	sessionStore := &fakeDashSessionStore{sessions: map[string][]oidc.RefreshSession{}}
	credStore := &fakeDashCredStore{}
	// relay = nil → graceful absence.
	h := newTestDashHandler(t, consentStore, sessionStore, credStore, nil)

	rec := httptest.NewRecorder()
	r := authedCtxRequest(http.MethodGet, "/dashboard/relay", "user-a")
	h.GetRelayToggles(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (graceful absent, not 503)", rec.Code)
	}
	body := rec.Body.String()
	// The template renders the absent-state message when RelayAbsent is true.
	if !strings.Contains(body, "not available") && !strings.Contains(body, "unavailable") {
		t.Error("relay absent state not reflected in response body")
	}
}

// TestDashboard_XSSEscaping verifies that a client ID containing a raw HTML
// script tag is contextually escaped by html/template and does NOT appear as
// executable markup in the rendered output (INVARIANT §5).
func TestDashboard_XSSEscaping(t *testing.T) {
	const xssPayload = "<script>alert('xss')</script>"
	consentStore := &fakeDashConsentStore{
		grants: map[string][]oidc.ConsentGrant{
			"user-xss": {
				{
					ID:        "grant-xss",
					UserID:    "user-xss",
					ClientID:  xssPayload,
					GrantedAt: time.Now(),
				},
			},
		},
	}
	sessionStore := &fakeDashSessionStore{sessions: map[string][]oidc.RefreshSession{}}
	credStore := &fakeDashCredStore{}
	h := newTestDashHandler(t, consentStore, sessionStore, credStore, nil)

	rec := httptest.NewRecorder()
	r := authedCtxRequest(http.MethodGet, "/dashboard/apps", "user-xss")
	h.GetConnectedApps(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	// Raw script tag must never appear in the rendered output.
	if strings.Contains(body, "<script>") {
		t.Error("XSS: raw <script> present in output — html/template contextual escaping failed")
	}
	// The HTML-escaped form must be present, proving the data was rendered (not dropped).
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("XSS: expected HTML-escaped form not found in output; body snippet: %s",
			body[max(0, strings.Index(body, "grant")-50):min(len(body), strings.Index(body, "grant")+200)])
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
