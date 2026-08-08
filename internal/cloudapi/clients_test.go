package cloudapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/clients"
	cloudopenapi "github.com/harbor-auth/harbor/internal/gen/openapi/cloud"
)

// fakeClientStore is a minimal, stateful in-memory ClientProvisioningStore
// fake shared by every *_test.go file in this package that needs a Server —
// mirrors memQuerier's role for *Store (sessions_test.go).
type fakeClientStore struct {
	mu      sync.Mutex
	clients map[string]clients.NamespacedClient // keyed by client_id
	// createErrOverride, if non-nil, is returned (and cleared) by the next
	// Create call instead of the normal in-memory logic. Used to deterministically
	// exercise cloudapi's mapping of clients.ErrNamespaceInactive to 404
	// namespace_not_found (H2 TOCTOU backstop) without needing an actual
	// concurrent race — the real race-closure proof runs against real
	// Postgres in internal/cloudapi/integration_test.go, since a fake this
	// simple cannot reproduce a genuine INSERT ... WHERE EXISTS race.
	createErrOverride error
}

func newFakeClientStore() *fakeClientStore {
	return &fakeClientStore{clients: map[string]clients.NamespacedClient{}}
}

func (f *fakeClientStore) Create(_ context.Context, c clients.NewNamespacedClient) (clients.NamespacedClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErrOverride != nil {
		err := f.createErrOverride
		f.createErrOverride = nil
		return clients.NamespacedClient{}, err
	}
	if _, exists := f.clients[c.ClientID]; exists {
		return clients.NamespacedClient{}, clients.ErrNamespacedClientExists
	}
	row := clients.NamespacedClient{
		ClientID:                c.ClientID,
		NamespaceID:             c.NamespaceID,
		Name:                    c.Name,
		SectorID:                c.SectorID,
		RedirectURIs:            c.RedirectURIs,
		TokenFormat:             c.TokenFormat,
		ScopesAllowed:           c.ScopesAllowed,
		ClientSecretHash:        c.ClientSecretHash,
		GrantTypes:              c.GrantTypes,
		ResponseTypes:           c.ResponseTypes,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		CreatedAt:               c.CreatedAt,
	}
	f.clients[c.ClientID] = row
	return row, nil
}

func (f *fakeClientStore) Get(_ context.Context, clientID, namespaceID string) (clients.NamespacedClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.clients[clientID]
	if !ok || row.DeletedAt != nil || row.NamespaceID != namespaceID {
		return clients.NamespacedClient{}, clients.ErrClientNotFound
	}
	return row, nil
}

func (f *fakeClientStore) List(_ context.Context, namespaceID string) ([]clients.NamespacedClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []clients.NamespacedClient
	for _, row := range f.clients {
		if row.DeletedAt == nil && row.NamespaceID == namespaceID {
			out = append(out, row)
		}
	}
	return out, nil
}

func (f *fakeClientStore) Update(_ context.Context, c clients.UpdateNamespacedClient) (clients.NamespacedClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.clients[c.ClientID]
	if !ok || row.DeletedAt != nil || row.NamespaceID != c.NamespaceID {
		return clients.NamespacedClient{}, clients.ErrClientNotFound
	}
	row.Name = c.Name
	row.RedirectURIs = c.RedirectURIs
	row.ScopesAllowed = c.ScopesAllowed
	row.TokenEndpointAuthMethod = c.TokenEndpointAuthMethod
	// Mirrors the real store's COALESCE semantics: a nil hash leaves the
	// stored one untouched.
	if c.ClientSecretHash != nil {
		row.ClientSecretHash = c.ClientSecretHash
	}
	f.clients[c.ClientID] = row
	return row, nil
}

func (f *fakeClientStore) SoftDelete(_ context.Context, clientID, namespaceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.clients[clientID]
	if !ok || row.DeletedAt != nil || row.NamespaceID != namespaceID {
		return nil // mirrors the real store: absent/foreign/already-deleted is a no-op
	}
	now := time.Now().UTC()
	row.DeletedAt = &now
	f.clients[clientID] = row
	return nil
}

// SoftDeleteAllForNamespace mirrors DBNamespacedClientStore.SoftDeleteAllForNamespace
// (H2): every live client owned by namespaceID is marked deleted. Owning no
// live clients is not an error — the real UPDATE simply affects zero rows.
func (f *fakeClientStore) SoftDeleteAllForNamespace(_ context.Context, namespaceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now().UTC()
	for id, row := range f.clients {
		if row.DeletedAt == nil && row.NamespaceID == namespaceID {
			row.DeletedAt = &now
			f.clients[id] = row
		}
	}
	return nil
}

// get is a test-only convenience over the fake's internal map, bypassing the
// namespace/deleted_at filtering Get applies — used where a test needs to
// inspect a row regardless of ownership (e.g. asserting sector_id on the
// persisted record).
func (f *fakeClientStore) row(clientID string) (clients.NamespacedClient, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.clients[clientID]
	return row, ok
}

// newTestServerWithClients builds a Server over a fresh memQuerier-backed
// Store and a fresh fakeClientStore, returning both fakes so tests can seed
// namespaces and inspect persisted client rows directly.
func newTestServerWithClients() (*Server, *memQuerier, *fakeClientStore) {
	q := newMemQuerier()
	cs := newFakeClientStore()
	return NewServer(NewStore(q), cs), q, cs
}

// --- request helpers ---------------------------------------------------

func doPostClient(t *testing.T, srv *Server, namespace, idempotencyKey, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/namespaces/"+namespace+"/clients", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.PostAdminV1NamespacesClients(rec, req, namespace, cloudopenapi.PostAdminV1NamespacesClientsParams{IdempotencyKey: idempotencyKey})
	return rec
}

func doGetClient(t *testing.T, srv *Server, namespace, clientID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/namespaces/"+namespace+"/clients/"+clientID, nil)
	rec := httptest.NewRecorder()
	srv.GetAdminV1NamespacesClient(rec, req, namespace, clientID)
	return rec
}

func doListClients(t *testing.T, srv *Server, namespace string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/namespaces/"+namespace+"/clients", nil)
	rec := httptest.NewRecorder()
	srv.GetAdminV1NamespacesClients(rec, req, namespace)
	return rec
}

func doPutClient(t *testing.T, srv *Server, namespace, clientID, idempotencyKey, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/namespaces/"+namespace+"/clients/"+clientID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.PutAdminV1NamespacesClient(rec, req, namespace, clientID, cloudopenapi.PutAdminV1NamespacesClientParams{IdempotencyKey: idempotencyKey})
	return rec
}

func doDeleteClient(t *testing.T, srv *Server, namespace, clientID, idempotencyKey string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/namespaces/"+namespace+"/clients/"+clientID, nil)
	rec := httptest.NewRecorder()
	srv.DeleteAdminV1NamespacesClient(rec, req, namespace, clientID, cloudopenapi.DeleteAdminV1NamespacesClientParams{IdempotencyKey: idempotencyKey})
	return rec
}

// validSecretHash64Hex is a syntactically valid (64 lowercase hex chars)
// client_secret_hash used across tests that don't care about its specific
// value.
const validSecretHash64Hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// --- create ------------------------------------------------------------

func TestPostAdminV1NamespacesClientsCreatesClient(t *testing.T) {
	srv, q, _ := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")

	rec := doPostClient(t, srv, "tenant-a", "create-key-1",
		`{"client_id":"client-aaaaaaaa","redirect_uris":["https://a.example.com/cb"],"client_secret_hash":"`+validSecretHash64Hex+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	var resp cloudopenapi.ClientResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ClientId != "client-aaaaaaaa" || resp.NamespaceId != "tenant-a" {
		t.Fatalf("response = %#v", resp)
	}
	if resp.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Errorf("TokenEndpointAuthMethod = %q, want client_secret_basic (default)", resp.TokenEndpointAuthMethod)
	}
	if resp.GrantTypes == nil || len(*resp.GrantTypes) != 2 {
		t.Errorf("GrantTypes = %v, want [authorization_code refresh_token] default", resp.GrantTypes)
	}
}

// TestPostAdminV1NamespacesClientsNamespaceDeletedBetweenCheckAndInsertReturns404
// is the deterministic half of H2's TOCTOU fix (the real race-closure proof,
// against actual concurrent goroutines and real Postgres, lives in
// internal/cloudapi/integration_test.go). namespaceActive above passes (the
// fake namespace is active), but clientStore.Create simulates a namespace
// that was deleted in the window between that check and the store call — the
// exact interleaving a concurrent DELETE /admin/v1/namespaces/{id} produces
// against the real INSERT ... WHERE EXISTS query
// (db/queries/relying_parties.sql). The handler must map
// clients.ErrNamespaceInactive to the same 404 namespace_not_found
// namespaceActive itself would have produced, and must not persist anything.
func TestPostAdminV1NamespacesClientsNamespaceDeletedBetweenCheckAndInsertReturns404(t *testing.T) {
	srv, q, cs := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")
	cs.createErrOverride = clients.ErrNamespaceInactive

	rec := doPostClient(t, srv, "tenant-a", "toctou-key",
		`{"client_id":"client-toctou1","redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec).Code; got != cloudopenapi.ErrorCodeNamespaceNotFound {
		t.Fatalf("error code = %q, want namespace_not_found", got)
	}
	if _, ok := cs.row("client-toctou1"); ok {
		t.Fatal("client-toctou1 was persisted despite Create() reporting the namespace inactive")
	}
}

// TestPostAdminV1NamespacesClientsSectorIDEqualsClientID inspects the
// persisted row directly through the fake store (the response does not
// carry sector_id) to prove PPID sector isolation: register.go's dynamic
// registration uses the same pattern for the same reason.
func TestPostAdminV1NamespacesClientsSectorIDEqualsClientID(t *testing.T) {
	srv, q, cs := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")

	doPostClient(t, srv, "tenant-a", "create-key-2",
		`{"client_id":"client-bbbbbbbb","redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none"}`)

	stored, ok := cs.row("client-bbbbbbbb")
	if !ok {
		t.Fatal("client-bbbbbbbb not persisted")
	}
	if stored.SectorID != stored.ClientID {
		t.Errorf("SectorID = %q, want %q (client's own id)", stored.SectorID, stored.ClientID)
	}
}

// TestPostAdminV1NamespacesClientsResponseHasNoSecretFields asserts on the
// RAW JSON keys of the response — not the Go struct, which by construction
// has no such field — so a future response-shape change can't silently
// reintroduce a leak without this test failing.
func TestPostAdminV1NamespacesClientsResponseHasNoSecretFields(t *testing.T) {
	srv, q, _ := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")

	rec := doPostClient(t, srv, "tenant-a", "create-key-3",
		`{"client_id":"client-cccccccc","redirect_uris":["https://a.example.com/cb"],"client_secret_hash":"`+validSecretHash64Hex+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode raw response: %v", err)
	}
	for key := range raw {
		if strings.Contains(strings.ToLower(key), "secret") {
			t.Errorf("response body contains key %q — a client_secret* field must never be echoed back", key)
		}
	}
}

func TestPostAdminV1NamespacesClientsNamespaceNotFound(t *testing.T) {
	srv, _, _ := newTestServerWithClients()
	rec := doPostClient(t, srv, "missing-ns", "create-key-4",
		`{"client_id":"client-dddddddd","redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec).Code; got != cloudopenapi.ErrorCodeNamespaceNotFound {
		t.Fatalf("error code = %q, want namespace_not_found", got)
	}
}

func TestPostAdminV1NamespacesClientsSoftDeletedNamespaceNotFound(t *testing.T) {
	srv, q, _ := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")
	if err := NewStore(q).SoftDeleteNamespace(context.Background(), "tenant-a"); err != nil {
		t.Fatalf("SoftDeleteNamespace: %v", err)
	}
	rec := doPostClient(t, srv, "tenant-a", "create-key-5",
		`{"client_id":"client-eeeeeeee","redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
}

func TestPostAdminV1NamespacesClientsDuplicateIDRejected(t *testing.T) {
	srv, q, _ := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")
	q.putNamespace("tenant-b", "active")

	doPostClient(t, srv, "tenant-a", "dup-key-1",
		`{"client_id":"client-ffffffff","redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none"}`)
	// Even a different namespace claiming the same client_id collides.
	rec := doPostClient(t, srv, "tenant-b", "dup-key-2-fresh",
		`{"client_id":"client-ffffffff","redirect_uris":["https://b.example.com/cb"],"token_endpoint_auth_method":"none"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body = %s", rec.Code, rec.Body.String())
	}
	errResp := decodeError(t, rec)
	if errResp.Code != cloudopenapi.ErrorCodeClientAlreadyExists {
		t.Fatalf("error code = %q, want client_already_exists", errResp.Code)
	}
	if strings.Contains(errResp.Message, "tenant-a") || strings.Contains(errResp.Message, "client-ffffffff") {
		t.Errorf("error message names the id or owner: %q", errResp.Message)
	}
}

func TestPostAdminV1NamespacesClientsIdempotentReplayIsByteIdentical(t *testing.T) {
	srv, q, _ := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")
	body := `{"client_id":"client-gggggggg","redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none"}`

	first := doPostClient(t, srv, "tenant-a", "replay-key-1", body)
	if first.Code != http.StatusCreated {
		t.Fatalf("first status = %d, want 201; body = %s", first.Code, first.Body.String())
	}
	second := doPostClient(t, srv, "tenant-a", "replay-key-1", body)
	if second.Code != http.StatusCreated {
		t.Fatalf("second status = %d, want 201; body = %s", second.Code, second.Body.String())
	}
	if first.Body.String() != second.Body.String() {
		t.Fatalf("replay body mismatch:\nfirst  = %s\nsecond = %s", first.Body.String(), second.Body.String())
	}
}

func TestPostAdminV1NamespacesClientsIdempotencyKeyReusedWithDifferentBody(t *testing.T) {
	srv, q, _ := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")

	doPostClient(t, srv, "tenant-a", "reuse-key-1",
		`{"client_id":"client-hhhhhhhh","redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none"}`)
	rec := doPostClient(t, srv, "tenant-a", "reuse-key-1",
		`{"client_id":"client-iiiiiiii","redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec).Code; got != cloudopenapi.ErrorCodeIdempotencyKeyReused {
		t.Fatalf("error code = %q, want idempotency_key_reused", got)
	}
}

// --- validation matrix -----------------------------------------------------

func TestPostAdminV1NamespacesClientsValidation(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "client_secret_hash bad length",
			body: `{"client_id":"client-val00001","redirect_uris":["https://a.example.com/cb"],"client_secret_hash":"abc123"}`,
		},
		{
			name: "client_secret_hash uppercase hex rejected",
			body: `{"client_id":"client-val00002","redirect_uris":["https://a.example.com/cb"],"client_secret_hash":"` + strings.ToUpper(validSecretHash64Hex) + `"}`,
		},
		{
			name: `token_endpoint_auth_method "none" with a hash is rejected`,
			body: `{"client_id":"client-val00003","redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none","client_secret_hash":"` + validSecretHash64Hex + `"}`,
		},
		{
			name: "client_secret_basic without a hash is rejected",
			body: `{"client_id":"client-val00004","redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"client_secret_basic"}`,
		},
		{
			// H1: an explicit "" must never be treated as "field omitted,
			// apply the default" — it must be rejected outright. Before the
			// fix this decoded into a non-nil *string pointing at "" (the
			// generated type is a bare `string`, so the OpenAPI enum is not
			// enforced at decode time), sailed through
			// ValidateTokenEndpointAuthMethod("") (which returns nil —
			// correctly, for its OTHER caller, mgmtapi's RFC 7591 register,
			// where a bare string field cannot distinguish omitted from
			// explicit-empty), and produced a client with a NULL
			// token_endpoint_auth_method — which internal/oidc/auth_method.go
			// maps to ClientAuthNone: a client admitted at /token with NO
			// credential check.
			name: `empty-string token_endpoint_auth_method is rejected, not defaulted`,
			body: `{"client_id":"client-val00011","redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":""}`,
		},
		{
			// Same H1 hole, but with a hash also supplied — the review's
			// second "Verified failure": pre-fix this stored the hash but the
			// client authenticated with none anyway (NULL auth method wins),
			// silently making the hash dead weight.
			name: `empty-string token_endpoint_auth_method with a hash is still rejected`,
			body: `{"client_id":"client-val00012","redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"","client_secret_hash":"` + validSecretHash64Hex + `"}`,
		},
		{
			name: "non-loopback http redirect_uri rejected",
			body: `{"client_id":"client-val00005","redirect_uris":["http://not-loopback.example.com/cb"],"token_endpoint_auth_method":"none"}`,
		},
		{
			name: "redirect_uri with a fragment rejected",
			body: `{"client_id":"client-val00006","redirect_uris":["https://a.example.com/cb#frag"],"token_endpoint_auth_method":"none"}`,
		},
		{
			name: "9 redirect_uris exceeds maxItems 8",
			body: `{"client_id":"client-val00007","redirect_uris":["https://a.example.com/1","https://a.example.com/2","https://a.example.com/3","https://a.example.com/4","https://a.example.com/5","https://a.example.com/6","https://a.example.com/7","https://a.example.com/8","https://a.example.com/9"],"token_endpoint_auth_method":"none"}`,
		},
		{
			name: "bad grant_type rejected",
			body: `{"client_id":"client-val00008","redirect_uris":["https://a.example.com/cb"],"grant_types":["implicit"]}`,
		},
		{
			name: "bad response_type rejected",
			body: `{"client_id":"client-val00009","redirect_uris":["https://a.example.com/cb"],"response_types":["token"]}`,
		},
		{
			name: "client_id too short (< 8 chars) rejected",
			body: `{"client_id":"short","redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none"}`,
		},
		{
			name: "no redirect_uris rejected",
			body: `{"client_id":"client-val00010","redirect_uris":[],"token_endpoint_auth_method":"none"}`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv, q, _ := newTestServerWithClients()
			q.putNamespace("tenant-a", "active")
			rec := doPostClient(t, srv, "tenant-a", "val-key-"+tt.name, tt.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
			}
			if got := decodeError(t, rec).Code; got != cloudopenapi.ErrorCodeInvalidRequest {
				t.Fatalf("error code = %q, want invalid_request", got)
			}
		})
	}
}

// --- get / list --------------------------------------------------------

func TestGetAdminV1NamespacesClientFound(t *testing.T) {
	srv, q, _ := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")
	doPostClient(t, srv, "tenant-a", "get-key-1", `{"client_id":"client-jjjjjjjj","redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none"}`)

	rec := doGetClient(t, srv, "tenant-a", "client-jjjjjjjj")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
}

func TestGetAdminV1NamespacesClientNotFound(t *testing.T) {
	srv, q, _ := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")
	rec := doGetClient(t, srv, "tenant-a", "never-existed-client")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec).Code; got != cloudopenapi.ErrorCodeClientNotFound {
		t.Fatalf("error code = %q, want client_not_found", got)
	}
}

func TestGetAdminV1NamespacesClientsListsOnlyThatNamespace(t *testing.T) {
	srv, q, _ := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")
	q.putNamespace("tenant-b", "active")

	doPostClient(t, srv, "tenant-a", "list-key-1", `{"client_id":"client-kkkkkkkk","redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none"}`)
	doPostClient(t, srv, "tenant-a", "list-key-2", `{"client_id":"client-llllllll","redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none"}`)
	doPostClient(t, srv, "tenant-b", "list-key-3", `{"client_id":"client-mmmmmmmm","redirect_uris":["https://b.example.com/cb"],"token_endpoint_auth_method":"none"}`)

	rec := doListClients(t, srv, "tenant-a")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var resp cloudopenapi.ClientListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Clients) != 2 {
		t.Fatalf("Clients = %d, want 2", len(resp.Clients))
	}
}

// --- update --------------------------------------------------------------

func TestPutAdminV1NamespacesClientUpdatesAndPreservesOmittedFields(t *testing.T) {
	srv, q, _ := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")
	doPostClient(t, srv, "tenant-a", "put-key-1",
		`{"client_id":"client-nnnnnnnn","client_name":"Original Name","redirect_uris":["https://a.example.com/cb"],"client_secret_hash":"`+validSecretHash64Hex+`","token_endpoint_auth_method":"client_secret_basic"}`)

	rec := doPutClient(t, srv, "tenant-a", "client-nnnnnnnn", "put-key-2",
		`{"redirect_uris":["https://a.example.com/cb2"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var resp cloudopenapi.ClientResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ClientName == nil || *resp.ClientName != "Original Name" {
		t.Errorf("ClientName = %v, want preserved \"Original Name\"", resp.ClientName)
	}
	if resp.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Errorf("TokenEndpointAuthMethod = %q, want preserved client_secret_basic", resp.TokenEndpointAuthMethod)
	}
	if len(resp.RedirectUris) != 1 || resp.RedirectUris[0] != "https://a.example.com/cb2" {
		t.Errorf("RedirectUris = %v, want updated", resp.RedirectUris)
	}
}

func TestPutAdminV1NamespacesClientNotFound(t *testing.T) {
	srv, q, _ := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")
	rec := doPutClient(t, srv, "tenant-a", "never-existed-client", "put-key-3", `{"redirect_uris":["https://a.example.com/cb"]}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec).Code; got != cloudopenapi.ErrorCodeClientNotFound {
		t.Fatalf("error code = %q, want client_not_found", got)
	}
}

// TestPutAdminV1NamespacesClientEmptyAuthMethodDoesNotDowngradeClient is the
// review's third "Verified failure": PUT {"redirect_uris":[...],
// "token_endpoint_auth_method":""} against a LIVE client_secret_basic client
// must be rejected — not silently accepted and used to downgrade the client
// to public (token_endpoint_auth_method NULL -> ClientAuthNone in
// internal/oidc/auth_method.go), which is an authentication bypass for
// anyone who already knows the client_id (H1).
func TestPutAdminV1NamespacesClientEmptyAuthMethodDoesNotDowngradeClient(t *testing.T) {
	srv, q, cs := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")
	doPostClient(t, srv, "tenant-a", "put-empty-am-create",
		`{"client_id":"client-ppppppppp","redirect_uris":["https://a.example.com/cb"],"client_secret_hash":"`+validSecretHash64Hex+`","token_endpoint_auth_method":"client_secret_basic"}`)

	rec := doPutClient(t, srv, "tenant-a", "client-ppppppppp", "put-empty-am-attempt",
		`{"redirect_uris":["https://a.example.com/cb2"],"token_endpoint_auth_method":""}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec).Code; got != cloudopenapi.ErrorCodeInvalidRequest {
		t.Fatalf("error code = %q, want invalid_request", got)
	}

	// The client must still be exactly as it was: confidential, with its
	// hash intact — the rejected PUT must not have mutated anything.
	row, ok := cs.row("client-ppppppppp")
	if !ok {
		t.Fatal("client-ppppppppp vanished")
	}
	if row.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Fatalf("TokenEndpointAuthMethod = %q, want unchanged client_secret_basic (rejected PUT must not downgrade)", row.TokenEndpointAuthMethod)
	}
	if len(row.ClientSecretHash) == 0 {
		t.Fatal("ClientSecretHash was cleared by a rejected PUT")
	}
}

// TestPutAdminV1NamespacesClientEmptySecretHashIsRejected is M1's proof:
// PUT {"client_secret_hash":""} must be rejected outright, never silently
// treated as "hash omitted" (which UpdateNamespacedClient's COALESCE would
// turn into "leave the stored hash untouched" — exactly the
// none-with-a-retained-hash state H1 forbids, and a trap for a later PUT
// that switches back to a confidential method under a secret the operator
// believed removed).
func TestPutAdminV1NamespacesClientEmptySecretHashIsRejected(t *testing.T) {
	srv, q, cs := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")
	doPostClient(t, srv, "tenant-a", "put-empty-hash-create",
		`{"client_id":"client-qqqqqqqqq","redirect_uris":["https://a.example.com/cb"],"client_secret_hash":"`+validSecretHash64Hex+`","token_endpoint_auth_method":"client_secret_basic"}`)

	rec := doPutClient(t, srv, "tenant-a", "client-qqqqqqqqq", "put-empty-hash-attempt",
		`{"redirect_uris":["https://a.example.com/cb2"],"token_endpoint_auth_method":"none","client_secret_hash":""}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec).Code; got != cloudopenapi.ErrorCodeInvalidRequest {
		t.Fatalf("error code = %q, want invalid_request", got)
	}

	row, ok := cs.row("client-qqqqqqqqq")
	if !ok {
		t.Fatal("client-qqqqqqqqq vanished")
	}
	if row.TokenEndpointAuthMethod != "client_secret_basic" || len(row.ClientSecretHash) == 0 {
		t.Fatalf("client mutated by a rejected PUT: auth_method=%q hash_len=%d", row.TokenEndpointAuthMethod, len(row.ClientSecretHash))
	}
}

// --- delete --------------------------------------------------------------

// TestDeleteAdminV1NamespacesClientSoftDeletesThenGetIsNotFound proves the
// handler-level contract over fakeClientStore: after DELETE, GET reports
// client_not_found. It does NOT — and, over a fake store that reimplements
// deleted_at filtering rather than exercising real SQL, cannot — prove that
// authentication itself stops (L1). That proof requires the real
// GetRelyingParty query and oidc.AuthenticateClient, and lives in
// integration_test.go's TestIntegrationClientSoftDeleteStopsAuthentication,
// which runs against real PostgreSQL. This test was previously named
// ...SoftDeletesAndStopsAuthentication despite never touching an
// authentication path — renamed so its name matches what it actually checks.
func TestDeleteAdminV1NamespacesClientSoftDeletesThenGetIsNotFound(t *testing.T) {
	srv, q, _ := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")
	doPostClient(t, srv, "tenant-a", "del-key-1", `{"client_id":"client-oooooooo","redirect_uris":["https://a.example.com/cb"],"token_endpoint_auth_method":"none"}`)

	rec := doDeleteClient(t, srv, "tenant-a", "client-oooooooo", "del-key-2")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
	}

	get := doGetClient(t, srv, "tenant-a", "client-oooooooo")
	if get.Code != http.StatusNotFound {
		t.Fatalf("GET after delete status = %d, want 404; body = %s", get.Code, get.Body.String())
	}
}

func TestDeleteAdminV1NamespacesClientIdempotentOnAbsent(t *testing.T) {
	srv, q, _ := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")
	rec := doDeleteClient(t, srv, "tenant-a", "never-existed", "del-key-3")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
	}
}

// TestDeleteAdminV1NamespacesClientRejectsMalformedPathParameters is L2's
// proof: unlike POST/PUT, DELETE previously validated neither namespace nor
// client_id against their documented patterns at all before hashing them
// into the idempotency ledger key.
func TestDeleteAdminV1NamespacesClientRejectsMalformedPathParameters(t *testing.T) {
	srv, q, _ := newTestServerWithClients()
	q.putNamespace("tenant-a", "active")

	tests := []struct {
		name      string
		namespace string
		clientID  string
	}{
		{name: "client_id too short", namespace: "tenant-a", clientID: "short"},
		{name: "client_id has invalid characters", namespace: "tenant-a", clientID: "bad$id$$$$"},
		{name: "namespace has invalid characters", namespace: "Not_Valid", clientID: "client-rrrrrrrr"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := doDeleteClient(t, srv, tt.namespace, tt.clientID, "del-malformed-"+tt.name)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
			}
			if got := decodeError(t, rec).Code; got != cloudopenapi.ErrorCodeInvalidRequest {
				t.Fatalf("error code = %q, want invalid_request", got)
			}
		})
	}
}

// TestHashClientDeleteRequestIsInjective proves L2's fix: the classic
// ambiguous-concatenation collision the review flagged for a single
// separator byte — namespace `"a\x00"` + clientID `"b"` vs namespace `"a"` +
// clientID `"\x00b"`, both of which produce the literal byte string
// `a\x00\x00b` under naive concatenation — must now hash differently.
func TestHashClientDeleteRequestIsInjective(t *testing.T) {
	h1 := hashClientDeleteRequest("a\x00", "b")
	h2 := hashClientDeleteRequest("a", "\x00b")
	if h1 == h2 {
		t.Fatal("hashClientDeleteRequest(\"a\\x00\", \"b\") == hashClientDeleteRequest(\"a\", \"\\x00b\") — not injective")
	}
}

// --- resolveExplicitAuthMethod / validateAuthMethodSecretPairing (Go-level) ---

func TestResolveExplicitAuthMethodRejectsEmptyString(t *testing.T) {
	rec := httptest.NewRecorder()
	_, ok := resolveExplicitAuthMethod(rec, "")
	if ok {
		t.Fatal("resolveExplicitAuthMethod(\"\") = ok true, want false")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestResolveExplicitAuthMethodAcceptsKnownValues(t *testing.T) {
	for _, method := range []string{"none", "client_secret_basic", "client_secret_post"} {
		rec := httptest.NewRecorder()
		got, ok := resolveExplicitAuthMethod(rec, method)
		if !ok || got != method {
			t.Errorf("resolveExplicitAuthMethod(%q) = (%q, %v), want (%q, true)", method, got, ok, method)
		}
	}
}

// TestValidateAuthMethodSecretPairingFailsClosedOnUnknownMethod proves the
// switch's new default: branch — the exact spot where an empty-string
// authMethod once matched no case and fell through to ok=true (H1).
func TestValidateAuthMethodSecretPairingFailsClosedOnUnknownMethod(t *testing.T) {
	for _, tt := range []struct {
		authMethod    string
		hasSecretHash bool
	}{
		{authMethod: "", hasSecretHash: false},
		{authMethod: "", hasSecretHash: true},
		{authMethod: "private_key_jwt", hasSecretHash: false},
	} {
		if _, ok := validateAuthMethodSecretPairing(tt.authMethod, tt.hasSecretHash); ok {
			t.Errorf("validateAuthMethodSecretPairing(%q, %v) = ok true, want false (fail closed)", tt.authMethod, tt.hasSecretHash)
		}
	}
}

// --- clientResponse (L7) ----------------------------------------------------

// TestClientResponseEmptyGrantAndResponseTypesMarshalAsEmptyArrays proves L7:
// a client with no grant_types/response_types must serialize those fields as
// JSON "[]", never "null" — cloudopenapi.ClientResponse declares them as
// *[]string, and a non-nil pointer to a nil slice marshals as "null".
func TestClientResponseEmptyGrantAndResponseTypesMarshalAsEmptyArrays(t *testing.T) {
	resp := clientResponse(clients.NamespacedClient{ClientID: "c", NamespaceID: "n"})
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, field := range []string{`"grant_types":[]`, `"response_types":[]`} {
		if !strings.Contains(string(body), field) {
			t.Errorf("response body = %s, want it to contain %s", body, field)
		}
	}
}
