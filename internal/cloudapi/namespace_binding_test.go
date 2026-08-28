package cloudapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cloudopenapi "github.com/harbor-auth/harbor/internal/gen/openapi/cloud"
)

// This file pins the M5 per-anchor namespace binding across EVERY
// namespace-scoped route, not just POST /admin/v1/user-sessions (which
// usersessions_test.go already covers).
//
// The gap these tests close: `ns=` in CLOUD_SERVICE_AUTH_PUBLIC_KEYS is the
// only thing separating two tenants who legitimately hold the same scope, and
// it was previously consulted by exactly one handler. Every other
// namespace-scoped route took its namespace straight from the caller's request
// and never checked it, so one tenant's bridge key could read, create,
// repoint, or delete another tenant's OIDC clients.

// anchorBoundTo returns the ServiceClaims shape ParseTrustAnchorsEnv produces
// for an anchor line carrying `ns=<id>` — permitted for that namespace and
// nothing else. allNamespaces stays false, which is what makes the binding
// restrictive.
func anchorBoundTo(namespace string) ServiceClaims {
	return ServiceClaims{
		Subject:           "acme-bridge",
		allowedNamespaces: map[string]struct{}{namespace: {}},
	}
}

// unrestrictedAnchor is the legacy single-bridge shape: an anchor configured
// with no ns= token at all, which is deliberately permitted everywhere.
func unrestrictedAnchor() ServiceClaims {
	return ServiceClaims{Subject: "legacy-bridge", allNamespaces: true}
}

// withClaims attaches claims to r exactly as cloudAuthorized does in
// production after verifying the bearer token.
func withClaims(r *http.Request, claims ServiceClaims) *http.Request {
	return r.WithContext(WithServiceClaims(r.Context(), claims))
}

const bindingTestClientBody = `{"client_id":"attacker00","redirect_uris":["https://attacker.example/cb"],"token_endpoint_auth_method":"none"}`

// namespaceScopedRoute invokes one namespace-scoped handler against namespace
// ns, carrying the supplied caller claims.
type namespaceScopedRoute struct {
	name   string
	invoke func(s *Server, ns string, claims ServiceClaims) *httptest.ResponseRecorder
}

func namespaceScopedRoutes() []namespaceScopedRoute {
	return []namespaceScopedRoute{
		{"POST /namespaces/{ns}/clients", func(s *Server, ns string, c ServiceClaims) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodPost, "/admin/v1/namespaces/"+ns+"/clients", strings.NewReader(bindingTestClientBody))
			rec := httptest.NewRecorder()
			s.PostAdminV1NamespacesClients(rec, withClaims(r, c), ns,
				cloudopenapi.PostAdminV1NamespacesClientsParams{IdempotencyKey: "idem-" + ns + "-create"})
			return rec
		}},
		{"GET /namespaces/{ns}/clients", func(s *Server, ns string, c ServiceClaims) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodGet, "/admin/v1/namespaces/"+ns+"/clients", nil)
			rec := httptest.NewRecorder()
			s.GetAdminV1NamespacesClients(rec, withClaims(r, c), ns)
			return rec
		}},
		{"GET /namespaces/{ns}/clients/{id}", func(s *Server, ns string, c ServiceClaims) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodGet, "/admin/v1/namespaces/"+ns+"/clients/victim01", nil)
			rec := httptest.NewRecorder()
			s.GetAdminV1NamespacesClient(rec, withClaims(r, c), ns, "victim01")
			return rec
		}},
		{"PUT /namespaces/{ns}/clients/{id}", func(s *Server, ns string, c ServiceClaims) *httptest.ResponseRecorder {
			body := `{"redirect_uris":["https://attacker.example/cb"]}`
			r := httptest.NewRequest(http.MethodPut, "/admin/v1/namespaces/"+ns+"/clients/victim01", strings.NewReader(body))
			rec := httptest.NewRecorder()
			s.PutAdminV1NamespacesClient(rec, withClaims(r, c), ns, "victim01",
				cloudopenapi.PutAdminV1NamespacesClientParams{IdempotencyKey: "idem-" + ns + "-update"})
			return rec
		}},
		{"DELETE /namespaces/{ns}/clients/{id}", func(s *Server, ns string, c ServiceClaims) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodDelete, "/admin/v1/namespaces/"+ns+"/clients/victim01", nil)
			rec := httptest.NewRecorder()
			s.DeleteAdminV1NamespacesClient(rec, withClaims(r, c), ns, "victim01",
				cloudopenapi.DeleteAdminV1NamespacesClientParams{IdempotencyKey: "idem-" + ns + "-delete"})
			return rec
		}},
		{"GET /namespaces/{id}", func(s *Server, ns string, c ServiceClaims) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodGet, "/admin/v1/namespaces/"+ns, nil)
			rec := httptest.NewRecorder()
			s.GetAdminV1Namespace(rec, withClaims(r, c), ns)
			return rec
		}},
		{"DELETE /namespaces/{id}", func(s *Server, ns string, c ServiceClaims) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodDelete, "/admin/v1/namespaces/"+ns, nil)
			rec := httptest.NewRecorder()
			s.DeleteAdminV1Namespace(rec, withClaims(r, c), ns,
				cloudopenapi.DeleteAdminV1NamespaceParams{IdempotencyKey: "idem-" + ns + "-nsdelete"})
			return rec
		}},
		{"POST /namespaces (create)", func(s *Server, ns string, c ServiceClaims) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodPost, "/admin/v1/namespaces", strings.NewReader(`{"id":"`+ns+`"}`))
			rec := httptest.NewRecorder()
			s.PostAdminV1Namespaces(rec, withClaims(r, c),
				cloudopenapi.PostAdminV1NamespacesParams{IdempotencyKey: "idem-" + ns + "-nscreate"})
			return rec
		}},
	}
}

// TestNamespaceBindingRejectsForeignNamespace is the regression test for the
// cross-tenant gap: an anchor bound to "acme" must be refused on every
// namespace-scoped route when it names "globex" — even though "globex" exists
// and the anchor carries the route's required scope.
func TestNamespaceBindingRejectsForeignNamespace(t *testing.T) {
	for _, route := range namespaceScopedRoutes() {
		t.Run(route.name, func(t *testing.T) {
			s, _, _ := newTestServerWithClients()
			// Seed BOTH namespaces so a 403 can never be an artifact of the
			// target simply not existing.
			mustSeedNamespace(t, s, "acme")
			mustSeedNamespace(t, s, "globex")

			rec := route.invoke(s, "globex", anchorBoundTo("acme"))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 — an acme-bound anchor must not act on globex; body = %s",
					rec.Code, rec.Body.String())
			}
			if got := decodeError(t, rec); got.Code != cloudopenapi.ErrorCodeCrossTenantForbidden {
				t.Errorf("error.code = %q, want %q", got.Code, cloudopenapi.ErrorCodeCrossTenantForbidden)
			}
		})
	}
}

// TestNamespaceBindingIsNotAnExistenceOracle pins the ordering property: the
// binding is checked BEFORE any store lookup, so a restricted anchor gets the
// same 403 whether or not the namespace it names exists. A 404 here would let
// one tenant enumerate the other tenants on the deployment.
func TestNamespaceBindingIsNotAnExistenceOracle(t *testing.T) {
	for _, route := range namespaceScopedRoutes() {
		t.Run(route.name, func(t *testing.T) {
			s, _, _ := newTestServerWithClients()
			mustSeedNamespace(t, s, "acme")
			// "ghost" is deliberately NOT created.

			rec := route.invoke(s, "ghost", anchorBoundTo("acme"))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (never 404 — that would leak which namespaces exist); body = %s",
					rec.Code, rec.Body.String())
			}
		})
	}
}

// TestNamespaceBindingAllowsOwnNamespace is the false-positive guard: the same
// restricted anchor must still be able to work inside the namespace it IS
// bound to. Any non-403 status proves the request passed the binding check —
// the routes' own success/validation behaviour is covered elsewhere.
func TestNamespaceBindingAllowsOwnNamespace(t *testing.T) {
	for _, route := range namespaceScopedRoutes() {
		t.Run(route.name, func(t *testing.T) {
			s, _, _ := newTestServerWithClients()
			mustSeedNamespace(t, s, "acme")

			rec := route.invoke(s, "acme", anchorBoundTo("acme"))

			if rec.Code == http.StatusForbidden {
				t.Fatalf("status = 403 for the anchor's OWN namespace — the binding is over-restrictive; body = %s",
					rec.Body.String())
			}
		})
	}
}

// TestUnrestrictedAnchorReachesEveryNamespace pins the back-compat path: an
// anchor configured WITHOUT an ns= token (allNamespaces=true, the legacy
// single-bridge deployment) must keep reaching every namespace, so adding the
// binding cannot break an existing single-tenant install.
func TestUnrestrictedAnchorReachesEveryNamespace(t *testing.T) {
	for _, route := range namespaceScopedRoutes() {
		t.Run(route.name, func(t *testing.T) {
			s, _, _ := newTestServerWithClients()
			mustSeedNamespace(t, s, "globex")

			rec := route.invoke(s, "globex", unrestrictedAnchor())

			if rec.Code == http.StatusForbidden {
				t.Fatalf("status = 403 for an UNRESTRICTED anchor — back-compat broken; body = %s", rec.Body.String())
			}
		})
	}
}

// TestNamespaceBindingSkippedWithoutClaims documents the direct-invocation
// convention shared with PostUserSessions: with no ServiceClaims in context
// the handler was called outside the auth middleware (a unit test in
// isolation), so there is no anchor to bind to and the call is unrestricted.
// Production always has claims — cloudAuthorized attaches them before the
// handler runs.
func TestNamespaceBindingSkippedWithoutClaims(t *testing.T) {
	s, _, _ := newTestServerWithClients()
	mustSeedNamespace(t, s, "globex")

	r := httptest.NewRequest(http.MethodGet, "/admin/v1/namespaces/globex", nil)
	rec := httptest.NewRecorder()
	s.GetAdminV1Namespace(rec, r, "globex") // no claims attached

	if rec.Code == http.StatusForbidden {
		t.Fatalf("status = 403 with no claims in context; want the call treated as unrestricted; body = %s", rec.Body.String())
	}
}

func mustSeedNamespace(t *testing.T, s *Server, id string) {
	t.Helper()
	if _, err := s.store.CreateNamespace(context.Background(), id, "active"); err != nil {
		t.Fatalf("seed namespace %q: %v", id, err)
	}
}
