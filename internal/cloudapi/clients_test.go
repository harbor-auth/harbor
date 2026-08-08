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
}

func newFakeClientStore() *fakeClientStore {
	return &fakeClientStore{clients: map[string]clients.NamespacedClient{}}
}

func (f *fakeClientStore) Create(_ context.Context, c clients.NewNamespacedClient) (clients.NamespacedClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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

// --- delete --------------------------------------------------------------

func TestDeleteAdminV1NamespacesClientSoftDeletesAndStopsAuthentication(t *testing.T) {
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
