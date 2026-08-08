// clients_isolation_test.go is THE load-bearing suite for namespace-scoped
// OIDC client CRUD: it proves cross-tenant access is structurally impossible,
// not just checked, across every one of the five routes. See clients.go's
// package doc and db/queries/relying_parties.sql's namespaced queries for
// the WHERE-clause discipline this suite exercises end-to-end.
package cloudapi

import (
	"encoding/json"
	"testing"

	"github.com/harbor-auth/harbor/internal/clients"
	cloudopenapi "github.com/harbor-auth/harbor/internal/gen/openapi/cloud"
)

// clientBodyNoAuth returns a minimal valid client create body.
// token_endpoint_auth_method "none" keeps every fixture in this suite free
// of the create-time secret-hash pairing rule, which is exercised
// separately in clients_test.go.
func clientBodyNoAuth(clientID string, redirectURI string) string {
	return `{"client_id":"` + clientID + `","redirect_uris":["` + redirectURI + `"],"token_endpoint_auth_method":"none"}`
}

// TestClientIsolationCrossTenantAccessIsStructurallyImpossible seeds two
// namespaces (tenant-a, tenant-b), provisions client-a into tenant-a only,
// and then — with a single valid clients:read/clients:write token — proves
// tenant-b's view of client-a is indistinguishable from a client that never
// existed anywhere, in both directions (read and write), while tenant-a's
// row is completely unaffected by tenant-b's attempts.
func TestClientIsolationCrossTenantAccessIsStructurallyImpossible(t *testing.T) {
	srv, q, cs := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")
	q.putNamespace("tenant-b", "active")

	createRec := doPostClient(t, srv, "tenant-a", "iso-create-key",
		clientBodyNoAuth("isolation-client-a", "https://tenant-a.example.com/cb"))
	if createRec.Code != 201 {
		t.Fatalf("seed create status = %d, want 201; body = %s", createRec.Code, createRec.Body.String())
	}

	// --- GET via tenant-b: 404, body byte-identical to a nowhere-existing id ---
	gotForeign := doGetClient(t, srv, "tenant-b", "isolation-client-a")
	gotAbsent := doGetClient(t, srv, "tenant-b", "an-id-that-has-never-existed")
	if gotForeign.Code != 404 || gotAbsent.Code != 404 {
		t.Fatalf("GET status foreign=%d absent=%d, want 404, 404", gotForeign.Code, gotAbsent.Code)
	}
	if gotForeign.Body.String() != gotAbsent.Body.String() {
		t.Fatalf("GET body for a foreign-owned id differs from an absent id:\nforeign = %s\nabsent  = %s",
			gotForeign.Body.String(), gotAbsent.Body.String())
	}
	if got := decodeError(t, gotForeign).Code; got != cloudopenapi.ErrorCodeClientNotFound {
		t.Errorf("GET via wrong tenant error code = %q, want client_not_found (never a 403, which would confirm existence)", got)
	}

	// Snapshot tenant-a's row before every write attempt below, to diff
	// against afterward.
	before, ok := cs.row("isolation-client-a")
	if !ok {
		t.Fatal("isolation-client-a not persisted after seed create")
	}

	// --- PUT via tenant-b: 404, AND tenant-a's row unchanged afterward ---
	putRec := doPutClient(t, srv, "tenant-b", "isolation-client-a", "iso-put-key",
		`{"redirect_uris":["https://attacker.example.com/cb"],"client_name":"pwned"}`)
	if putRec.Code != 404 {
		t.Fatalf("PUT via wrong tenant status = %d, want 404; body = %s", putRec.Code, putRec.Body.String())
	}
	if got := decodeError(t, putRec).Code; got != cloudopenapi.ErrorCodeClientNotFound {
		t.Errorf("PUT via wrong tenant error code = %q, want client_not_found", got)
	}
	afterPut, ok := cs.row("isolation-client-a")
	if !ok {
		t.Fatal("isolation-client-a vanished after a rejected cross-tenant PUT")
	}
	assertClientRowUnchanged(t, "after cross-tenant PUT", before, afterPut)

	// --- DELETE via tenant-b: 204 (never leaks existence), AND tenant-a's row still live ---
	delRec := doDeleteClient(t, srv, "tenant-b", "isolation-client-a", "iso-delete-key")
	if delRec.Code != 204 {
		t.Fatalf("DELETE via wrong tenant status = %d, want 204 (idempotent no-op, never 404); body = %s", delRec.Code, delRec.Body.String())
	}
	afterDelete, ok := cs.row("isolation-client-a")
	if !ok {
		t.Fatal("isolation-client-a vanished after a cross-tenant DELETE — THIS is the case a naive implementation gets wrong")
	}
	if afterDelete.DeletedAt != nil {
		t.Fatal("isolation-client-a was soft-deleted by a cross-tenant DELETE request — a namespace deleted another namespace's live client")
	}
	assertClientRowUnchanged(t, "after cross-tenant DELETE", before, afterDelete)

	// --- LIST via tenant-b: omits it ---
	listRec := doListClients(t, srv, "tenant-b")
	if listRec.Code != 200 {
		t.Fatalf("LIST tenant-b status = %d, want 200; body = %s", listRec.Code, listRec.Body.String())
	}
	var listResp cloudopenapi.ClientListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	for _, c := range listResp.Clients {
		if c.ClientId == "isolation-client-a" {
			t.Fatalf("tenant-b's client list includes tenant-a's client isolation-client-a")
		}
	}

	// --- tenant-a can still fully operate on its own client ---
	getOwn := doGetClient(t, srv, "tenant-a", "isolation-client-a")
	if getOwn.Code != 200 {
		t.Fatalf("GET via owning tenant status = %d, want 200; body = %s", getOwn.Code, getOwn.Body.String())
	}
}

// assertClientRowUnchanged diffs every field of a NamespacedClient snapshot,
// failing loudly (naming the differing field) if anything moved.
func assertClientRowUnchanged(t *testing.T, when string, before, after clients.NamespacedClient) {
	t.Helper()
	if before.ClientID != after.ClientID {
		t.Errorf("%s: ClientID changed: %q -> %q", when, before.ClientID, after.ClientID)
	}
	if before.NamespaceID != after.NamespaceID {
		t.Errorf("%s: NamespaceID changed: %q -> %q", when, before.NamespaceID, after.NamespaceID)
	}
	if before.Name != after.Name {
		t.Errorf("%s: Name changed: %q -> %q", when, before.Name, after.Name)
	}
	if before.SectorID != after.SectorID {
		t.Errorf("%s: SectorID changed: %q -> %q", when, before.SectorID, after.SectorID)
	}
	if !stringSlicesEqual(before.RedirectURIs, after.RedirectURIs) {
		t.Errorf("%s: RedirectURIs changed: %v -> %v", when, before.RedirectURIs, after.RedirectURIs)
	}
	if !stringSlicesEqual(before.ScopesAllowed, after.ScopesAllowed) {
		t.Errorf("%s: ScopesAllowed changed: %v -> %v", when, before.ScopesAllowed, after.ScopesAllowed)
	}
	if before.TokenEndpointAuthMethod != after.TokenEndpointAuthMethod {
		t.Errorf("%s: TokenEndpointAuthMethod changed: %q -> %q", when, before.TokenEndpointAuthMethod, after.TokenEndpointAuthMethod)
	}
	if string(before.ClientSecretHash) != string(after.ClientSecretHash) {
		t.Errorf("%s: ClientSecretHash changed", when)
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestClientIsolationSameIdempotencyKeyAcrossTenantsNeverReplays proves the
// cloud_operations idempotency ledger — whose primary key is
// (idempotency_key, operation), NOT namespace-scoped
// (db/migrations/0019_cloud_namespaces.up.sql) — cannot let two different
// namespaces collide on the same literal Idempotency-Key string: the second
// namespace's POST must be evaluated on its own merits (here, rejected as a
// distinct request), never silently replay the first namespace's cached
// response body (which would hand tenant-b a client it never created,
// possibly under tenant-a's ownership).
func TestClientIsolationSameIdempotencyKeyAcrossTenantsNeverReplays(t *testing.T) {
	srv, q, _ := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")
	q.putNamespace("tenant-b", "active")

	const sharedKey = "shared-idempotency-key-both-tenants-use"

	firstRec := doPostClient(t, srv, "tenant-a", sharedKey, clientBodyNoAuth("shared-key-client-a", "https://tenant-a.example.com/cb"))
	if firstRec.Code != 201 {
		t.Fatalf("tenant-a create status = %d, want 201; body = %s", firstRec.Code, firstRec.Body.String())
	}

	secondRec := doPostClient(t, srv, "tenant-b", sharedKey, clientBodyNoAuth("shared-key-client-b", "https://tenant-b.example.com/cb"))
	if secondRec.Code != 409 {
		t.Fatalf("tenant-b create with tenant-a's Idempotency-Key status = %d, want 409 (a fresh request, never a replay); body = %s",
			secondRec.Code, secondRec.Body.String())
	}
	if got := decodeError(t, secondRec).Code; got != cloudopenapi.ErrorCodeIdempotencyKeyReused {
		t.Fatalf("error code = %q, want idempotency_key_reused", got)
	}
	if secondRec.Body.String() == firstRec.Body.String() {
		t.Fatal("tenant-b's response body is byte-identical to tenant-a's — the ledger replayed across namespaces")
	}

	// tenant-b must not have received (or created) tenant-a's client under
	// any id.
	getA := doGetClient(t, srv, "tenant-b", "shared-key-client-a")
	if getA.Code != 404 {
		t.Fatalf("tenant-b GET of tenant-a's client status = %d, want 404; body = %s", getA.Code, getA.Body.String())
	}
	// And tenant-b's own attempted client must not have been created either
	// — the request was rejected before any Create call.
	getB := doGetClient(t, srv, "tenant-b", "shared-key-client-b")
	if getB.Code != 404 {
		t.Fatalf("tenant-b GET of its own rejected client status = %d, want 404 (create was rejected, nothing should exist); body = %s", getB.Code, getB.Body.String())
	}
}

// TestClientIsolationOperatorClientInvisibleToNamespacedRoutes proves a
// relying_parties row with namespace_id IS NULL (an operator-registered or
// RFC-7591-dynamically-registered client — db/migrations/0020's permanent
// terminal state) is invisible to every namespaced route, exactly like a
// client owned by a different namespace. This is exercised at the store
// layer (clients.DBNamespacedClientStore) via clients_test.go/registration
// coverage in internal/clients; here we assert the SAME property the fake
// store enforces so the handler-level behavior this suite otherwise proves
// is not accidentally relying on the fake being stricter than production.
func TestClientIsolationOperatorClientInvisibleToNamespacedRoutes(t *testing.T) {
	srv, q, cs := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")

	// Simulate an operator-registered client: present in the relying_parties
	// registry (the fake's map) but with NamespaceID == "" (NULL at the DB
	// layer) — never created through the namespaced create path.
	cs.mu.Lock()
	cs.clients["operator-client"] = clients.NamespacedClient{
		ClientID:     "operator-client",
		NamespaceID:  "",
		Name:         "Statically Registered",
		SectorID:     "operator-client",
		RedirectURIs: []string{"https://operator.example.com/cb"},
	}
	cs.mu.Unlock()

	if rec := doGetClient(t, srv, "tenant-a", "operator-client"); rec.Code != 404 {
		t.Errorf("GET operator client via tenant-a status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}

	listRec := doListClients(t, srv, "tenant-a")
	var listResp cloudopenapi.ClientListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	for _, c := range listResp.Clients {
		if c.ClientId == "operator-client" {
			t.Fatal("tenant-a's client list includes the NULL-namespace operator client")
		}
	}

	if rec := doDeleteClient(t, srv, "tenant-a", "operator-client", "operator-delete-key"); rec.Code != 204 {
		t.Fatalf("DELETE operator client via tenant-a status = %d, want 204 (idempotent no-op)", rec.Code)
	}
	after, ok := cs.row("operator-client")
	if !ok || after.DeletedAt != nil {
		t.Fatal("the NULL-namespace operator client was affected by a namespaced DELETE — namespace scoping did not hold for NULL")
	}
}
