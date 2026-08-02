package bff

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/oidc"
	"github.com/harbor-auth/harbor/web"
)

// okHandler is a trivial handler that always returns 200 OK, used as the
// inner handler when testing the CSRF middleware in isolation.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// --- checkDashboardCSRF unit tests ---

func TestCheckDashboardCSRF_SecFetchSite(t *testing.T) {
	cases := []struct {
		name    string
		sfs     string
		wantErr bool
	}{
		{"same-origin", "same-origin", false},
		{"same-site", "same-site", false},
		{"none", "none", false},
		{"cross-site", "cross-site", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			r.Header.Set("Sec-Fetch-Site", tc.sfs)
			err := checkDashboardCSRF(r)
			if (err != nil) != tc.wantErr {
				t.Errorf("checkDashboardCSRF() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestCheckDashboardCSRF_OriginFallback(t *testing.T) {
	cases := []struct {
		name    string
		origin  string
		host    string
		wantErr bool
	}{
		{"same origin", "https://harbor.example.com", "harbor.example.com", false},
		{"cross origin", "https://evil.example.com", "harbor.example.com", true},
		{"opaque null origin", "null", "harbor.example.com", true},
		{"malformed origin", "not-a-url", "harbor.example.com", true},
		{"no origin header", "", "harbor.example.com", false},
		{"origin with port match", "https://harbor.example.com:8443", "harbor.example.com:8443", false},
		{"origin with port mismatch", "https://harbor.example.com:9000", "harbor.example.com:8443", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			// No Sec-Fetch-Site — force Origin fallback path.
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			r.Host = tc.host
			err := checkDashboardCSRF(r)
			if (err != nil) != tc.wantErr {
				t.Errorf("checkDashboardCSRF() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// --- DashboardCSRF middleware integration tests ---

func TestDashboardCSRF_GetPassesThrough(t *testing.T) {
	h := DashboardCSRF(okHandler)
	r := httptest.NewRequest(http.MethodGet, "/dashboard/apps", nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site") // even cross-site GETs pass
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Errorf("GET cross-site: status = %d, want 200 (GETs not gated)", rec.Code)
	}
}

func TestDashboardCSRF_CrossSitePostRejected(t *testing.T) {
	h := DashboardCSRF(okHandler)
	r := httptest.NewRequest(http.MethodPost, "/dashboard/apps/g1/revoke", nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST cross-site Sec-Fetch-Site: status = %d, want 403", rec.Code)
	}
}

func TestDashboardCSRF_SameOriginPostAllowed(t *testing.T) {
	h := DashboardCSRF(okHandler)
	r := httptest.NewRequest(http.MethodPost, "/dashboard/apps/g1/revoke", nil)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Errorf("POST same-origin Sec-Fetch-Site: status = %d, want 200", rec.Code)
	}
}

func TestDashboardCSRF_NoHeadersAllowed(t *testing.T) {
	h := DashboardCSRF(okHandler)
	r := httptest.NewRequest(http.MethodPost, "/dashboard/relay/a1/deactivate", nil)
	// Neither header — SameSite=Strict is still active; middleware passes through.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Errorf("POST no headers: status = %d, want 200 (SameSite=Strict is primary guard)", rec.Code)
	}
}

// --- Route-level integration tests: cross-site POST => 403 on each mutating route ---

// newFullTestDashHandler returns a ServeMux with all dashboard routes registered
// and canned stores pre-populated for the four mutating route tests.
func newFullTestDashHandler(t *testing.T) *http.ServeMux {
	t.Helper()
	const userID = "test-user"

	consentStore := &fakeDashConsentStore{
		grants: map[string][]oidc.Grant{
			userID: {{ID: "grant-1", UserID: userID, ClientID: "app-1"}},
		},
	}
	sessionStore := &fakeDashSessionStore{
		sessions: map[string][]oidc.RefreshSession{
			userID: {{ID: "sess-1"}},
		},
	}
	credStore := &fakeDashCredStore{
		creds: map[string][]clients.DashboardCredential{},
	}
	relayStore := &fakeDashRelayStore{
		addresses: map[string][]DashboardRelayAddress{
			userID: {{ID: "addr-1"}},
		},
	}

	tmpl, err := web.ParseDashboardTemplates()
	if err != nil {
		t.Fatalf("ParseDashboardTemplates: %v", err)
	}
	h, err := NewDashboardHandler(consentStore, sessionStore, credStore, nil, relayStore, tmpl, nil)
	if err != nil {
		t.Fatalf("NewDashboardHandler: %v", err)
	}
	mux := http.NewServeMux()
	h.Routes(mux)
	return mux
}

// withUserCtx injects an authenticated full-scope user ID into the request context.
func withUserCtx(r *http.Request, userID string) *http.Request {
	ctx := ContextWithUserID(r.Context(), userID)
	ctx = ContextWithSessionScope(ctx, SessionScopeFull)
	return r.WithContext(ctx)
}

// fakeDashRelayStore is a minimal relay store for testing route-level CSRF.
type fakeDashRelayStore struct {
	addresses map[string][]DashboardRelayAddress
}

func (f *fakeDashRelayStore) ListByUser(_ context.Context, userID string) ([]DashboardRelayAddress, error) {
	return f.addresses[userID], nil
}

func (f *fakeDashRelayStore) Deactivate(_ context.Context, _ string) error {
	return nil
}

// mutatingRoutes lists the four dashboard POST routes that must be CSRF-gated.
var mutatingRoutes = []struct {
	name   string
	path   string
	pathKV [2]string // SetPathValue key, value
}{
	{
		name:   "revoke app",
		path:   "/dashboard/apps/grant-1/revoke",
		pathKV: [2]string{"grant_id", "grant-1"},
	},
	{
		name:   "revoke session",
		path:   "/dashboard/sessions/sess-1/revoke",
		pathKV: [2]string{"session_id", "sess-1"},
	},
	{
		name:   "revoke credential",
		path:   "/dashboard/credentials/cred-1/revoke",
		pathKV: [2]string{"credential_id", "cred-1"},
	},
	{
		name:   "deactivate relay",
		path:   "/dashboard/relay/addr-1/deactivate",
		pathKV: [2]string{"address_id", "addr-1"},
	},
}

// TestDashboardRoutes_CrossSitePost verifies that a cross-site POST to each of
// the four mutating dashboard routes returns 403, regardless of auth state.
func TestDashboardRoutes_CrossSitePost(t *testing.T) {
	mux := newFullTestDashHandler(t)

	for _, route := range mutatingRoutes {
		t.Run(route.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, route.path, nil)
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.SetPathValue(route.pathKV[0], route.pathKV[1])
			r = withUserCtx(r, "test-user")

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, r)

			if rec.Code != http.StatusForbidden {
				t.Errorf("%s: cross-site POST => status %d, want 403", route.name, rec.Code)
			}
		})
	}
}

// TestDashboardRoutes_SameOriginPost verifies that a same-origin POST to each
// mutating route is processed normally (not blocked by the CSRF middleware).
func TestDashboardRoutes_SameOriginPost(t *testing.T) {
	mux := newFullTestDashHandler(t)

	for _, route := range mutatingRoutes {
		t.Run(route.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, route.path, nil)
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			r.SetPathValue(route.pathKV[0], route.pathKV[1])
			r = withUserCtx(r, "test-user")

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, r)

			// The CSRF middleware must pass the request through; downstream
			// handlers may return 303 (redirect after mutation) or 404 for
			// ownership checks. Any status other than 403 is acceptable here —
			// we are only verifying the CSRF gate does not block same-origin
			// requests.
			if rec.Code == http.StatusForbidden {
				t.Errorf("%s: same-origin POST => 403 (blocked by CSRF), should be passed through", route.name)
			}
		})
	}
}

// TestDashboardRoutes_CrossOriginOriginHeader verifies that a cross-origin POST
// detected via the Origin fallback (no Sec-Fetch-Site) is also blocked.
func TestDashboardRoutes_CrossOriginOriginHeader(t *testing.T) {
	mux := newFullTestDashHandler(t)

	route := mutatingRoutes[0] // revoke app — representative
	r := httptest.NewRequest(http.MethodPost, route.path, nil)
	// No Sec-Fetch-Site; attacker supplies a cross-origin Origin header.
	r.Header.Set("Origin", "https://evil.example.com")
	r.Host = "harbor.example.com"
	r.SetPathValue(route.pathKV[0], route.pathKV[1])
	r = withUserCtx(r, "test-user")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin Origin header: status = %d, want 403", rec.Code)
	}
}
