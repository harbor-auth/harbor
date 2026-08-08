package clients

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor-auth/harbor/internal/gen/db"
)

// fakeNamespacedClientQuerier is a minimal namespacedClientQuerier fake,
// stateful (unlike store_test.go-style per-call fakes) because these tests
// need real persistence across multiple calls: create then get, create then
// update, create then soft-delete then get again.
type fakeNamespacedClientQuerier struct {
	rows map[string]db.RelyingParty // keyed by client_id
}

func newFakeNamespacedClientQuerier() *fakeNamespacedClientQuerier {
	return &fakeNamespacedClientQuerier{rows: make(map[string]db.RelyingParty)}
}

func (f *fakeNamespacedClientQuerier) CreateNamespacedClient(_ context.Context, arg db.CreateNamespacedClientParams) (db.RelyingParty, error) {
	if _, exists := f.rows[arg.ClientID]; exists {
		return db.RelyingParty{}, &pgconn.PgError{Code: "23505"}
	}
	row := db.RelyingParty{
		ClientID:                arg.ClientID,
		Name:                    arg.Name,
		SectorID:                arg.SectorID,
		RedirectUris:            arg.RedirectUris,
		TokenFormat:             arg.TokenFormat,
		ScopesAllowed:           arg.ScopesAllowed,
		ClientSecretHash:        arg.ClientSecretHash,
		GrantTypes:              arg.GrantTypes,
		ResponseTypes:           arg.ResponseTypes,
		TokenEndpointAuthMethod: arg.TokenEndpointAuthMethod,
		CreatedAt:               arg.CreatedAt,
		NamespaceID:             arg.NamespaceID,
	}
	f.rows[arg.ClientID] = row
	return row, nil
}

func (f *fakeNamespacedClientQuerier) GetNamespacedClient(_ context.Context, arg db.GetNamespacedClientParams) (db.RelyingParty, error) {
	row, ok := f.rows[arg.ClientID]
	if !ok || row.DeletedAt.Valid || !samePtrString(row.NamespaceID, arg.NamespaceID) {
		return db.RelyingParty{}, pgx.ErrNoRows
	}
	return row, nil
}

func (f *fakeNamespacedClientQuerier) ListNamespacedClients(_ context.Context, namespaceID *string) ([]db.RelyingParty, error) {
	var out []db.RelyingParty
	for _, row := range f.rows {
		if !row.DeletedAt.Valid && samePtrString(row.NamespaceID, namespaceID) {
			out = append(out, row)
		}
	}
	return out, nil
}

func (f *fakeNamespacedClientQuerier) UpdateNamespacedClient(_ context.Context, arg db.UpdateNamespacedClientParams) (db.RelyingParty, error) {
	row, ok := f.rows[arg.ClientID]
	if !ok || row.DeletedAt.Valid || !samePtrString(row.NamespaceID, arg.NamespaceID) {
		return db.RelyingParty{}, pgx.ErrNoRows
	}
	row.Name = arg.Name
	row.RedirectUris = arg.RedirectUris
	row.ScopesAllowed = arg.ScopesAllowed
	row.TokenEndpointAuthMethod = arg.TokenEndpointAuthMethod
	// Mirrors the real query's COALESCE(sqlc.narg('client_secret_hash'), client_secret_hash):
	// a nil argument leaves the stored hash untouched.
	if arg.ClientSecretHash != nil {
		row.ClientSecretHash = arg.ClientSecretHash
	}
	f.rows[arg.ClientID] = row
	return row, nil
}

func (f *fakeNamespacedClientQuerier) SoftDeleteNamespacedClient(_ context.Context, arg db.SoftDeleteNamespacedClientParams) error {
	row, ok := f.rows[arg.ClientID]
	if !ok || row.DeletedAt.Valid || !samePtrString(row.NamespaceID, arg.NamespaceID) {
		return nil // mirrors the real UPDATE affecting zero rows: not an error
	}
	row.DeletedAt = pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
	f.rows[arg.ClientID] = row
	return nil
}

func (f *fakeNamespacedClientQuerier) SoftDeleteNamespaceClients(_ context.Context, namespaceID *string) error {
	for id, row := range f.rows {
		if !row.DeletedAt.Valid && samePtrString(row.NamespaceID, namespaceID) {
			row.DeletedAt = pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
			f.rows[id] = row
		}
	}
	return nil
}

func samePtrString(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func newTestNamespacedClientStore() (*DBNamespacedClientStore, *fakeNamespacedClientQuerier) {
	q := newFakeNamespacedClientQuerier()
	return NewDBNamespacedClientStore(q), q
}

func TestDBNamespacedClientStoreCreateRoundTrip(t *testing.T) {
	store, _ := newTestNamespacedClientStore()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	created, err := store.Create(context.Background(), NewNamespacedClient{
		ClientID:                "client-a",
		NamespaceID:             "tenant-a",
		Name:                    "Tenant A App",
		SectorID:                "client-a",
		RedirectURIs:            []string{"https://a.example.com/cb"},
		TokenFormat:             "jwt",
		ScopesAllowed:           []string{"openid"},
		ClientSecretHash:        []byte("32-bytes-of-fake-sha256-hash!!!!"),
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		CreatedAt:               now,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ClientID != "client-a" || created.NamespaceID != "tenant-a" {
		t.Fatalf("Create() = %#v", created)
	}
	if created.SectorID != "client-a" {
		t.Errorf("SectorID = %q, want client-a (each client is its own PPID sector)", created.SectorID)
	}

	got, err := store.Get(context.Background(), "client-a", "tenant-a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "Tenant A App" || len(got.RedirectURIs) != 1 {
		t.Errorf("Get() = %#v", got)
	}
}

func TestDBNamespacedClientStoreCreateDuplicateReturnsErrExists(t *testing.T) {
	store, _ := newTestNamespacedClientStore()
	ctx := context.Background()
	newClient := NewNamespacedClient{
		ClientID:      "dupe",
		NamespaceID:   "tenant-a",
		RedirectURIs:  []string{"https://a.example.com/cb"},
		SectorID:      "dupe",
		TokenFormat:   "jwt",
		ScopesAllowed: []string{"openid"},
	}
	if _, err := store.Create(ctx, newClient); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	// Even a different namespace claiming the same client_id collides —
	// client_id is the table's primary key regardless of owning namespace.
	newClient.NamespaceID = "tenant-b"
	_, err := store.Create(ctx, newClient)
	if !errors.Is(err, ErrNamespacedClientExists) {
		t.Fatalf("Create() error = %v, want ErrNamespacedClientExists", err)
	}
}

func TestDBNamespacedClientStoreGetNotFoundReturnsErrClientNotFound(t *testing.T) {
	store, _ := newTestNamespacedClientStore()
	_, err := store.Get(context.Background(), "missing", "tenant-a")
	if !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("Get() error = %v, want ErrClientNotFound", err)
	}
}

func TestDBNamespacedClientStoreGetCrossTenantReturnsErrClientNotFound(t *testing.T) {
	store, _ := newTestNamespacedClientStore()
	ctx := context.Background()
	if _, err := store.Create(ctx, NewNamespacedClient{
		ClientID: "client-a", NamespaceID: "tenant-a", SectorID: "client-a",
		RedirectURIs: []string{"https://a.example.com/cb"}, TokenFormat: "jwt",
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := store.Get(ctx, "client-a", "tenant-b"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("Get() from wrong namespace error = %v, want ErrClientNotFound", err)
	}
}

func TestDBNamespacedClientStoreUpdateNilHashLeavesUnchanged(t *testing.T) {
	store, _ := newTestNamespacedClientStore()
	ctx := context.Background()
	original := []byte("original-hash-32-bytes-long!!!!")
	if _, err := store.Create(ctx, NewNamespacedClient{
		ClientID: "client-a", NamespaceID: "tenant-a", SectorID: "client-a",
		RedirectURIs: []string{"https://a.example.com/cb"}, TokenFormat: "jwt",
		ClientSecretHash: original,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated, err := store.Update(ctx, UpdateNamespacedClient{
		ClientID:      "client-a",
		NamespaceID:   "tenant-a",
		Name:          "renamed",
		RedirectURIs:  []string{"https://a.example.com/cb2"},
		ScopesAllowed: []string{"openid", "profile"},
		// ClientSecretHash intentionally left nil.
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != "renamed" {
		t.Errorf("Name = %q, want renamed", updated.Name)
	}
	if string(updated.ClientSecretHash) != string(original) {
		t.Errorf("ClientSecretHash changed on nil update: got %q, want unchanged %q", updated.ClientSecretHash, original)
	}
}

func TestDBNamespacedClientStoreUpdateNotFoundReturnsErrClientNotFound(t *testing.T) {
	store, _ := newTestNamespacedClientStore()
	_, err := store.Update(context.Background(), UpdateNamespacedClient{ClientID: "missing", NamespaceID: "tenant-a"})
	if !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("Update() error = %v, want ErrClientNotFound", err)
	}
}

func TestDBNamespacedClientStoreSoftDeleteOfAbsentRowIsNoOp(t *testing.T) {
	store, _ := newTestNamespacedClientStore()
	if err := store.SoftDelete(context.Background(), "never-existed", "tenant-a"); err != nil {
		t.Fatalf("SoftDelete() on absent row error = %v, want nil", err)
	}
}

func TestDBNamespacedClientStoreSoftDeleteThenGetIsNotFound(t *testing.T) {
	store, _ := newTestNamespacedClientStore()
	ctx := context.Background()
	if _, err := store.Create(ctx, NewNamespacedClient{
		ClientID: "client-a", NamespaceID: "tenant-a", SectorID: "client-a",
		RedirectURIs: []string{"https://a.example.com/cb"}, TokenFormat: "jwt",
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.SoftDelete(ctx, "client-a", "tenant-a"); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}
	if _, err := store.Get(ctx, "client-a", "tenant-a"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("Get() after soft delete error = %v, want ErrClientNotFound", err)
	}
}

func TestDBNamespacedClientStoreSoftDeleteCrossTenantIsNoOp(t *testing.T) {
	store, _ := newTestNamespacedClientStore()
	ctx := context.Background()
	if _, err := store.Create(ctx, NewNamespacedClient{
		ClientID: "client-a", NamespaceID: "tenant-a", SectorID: "client-a",
		RedirectURIs: []string{"https://a.example.com/cb"}, TokenFormat: "jwt",
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.SoftDelete(ctx, "client-a", "tenant-b"); err != nil {
		t.Fatalf("SoftDelete() from wrong namespace error = %v, want nil (no-op)", err)
	}
	// tenant-a's row must still be live.
	if _, err := store.Get(ctx, "client-a", "tenant-a"); err != nil {
		t.Fatalf("Get() after cross-tenant delete attempt: %v, want row still live", err)
	}
}

func TestDBNamespacedClientStoreSoftDeleteAllForNamespaceOnlyAffectsThatNamespace(t *testing.T) {
	store, _ := newTestNamespacedClientStore()
	ctx := context.Background()
	for _, c := range []NewNamespacedClient{
		{ClientID: "a1", NamespaceID: "tenant-a", SectorID: "a1", RedirectURIs: []string{"https://a1.example.com/cb"}, TokenFormat: "jwt"},
		{ClientID: "a2", NamespaceID: "tenant-a", SectorID: "a2", RedirectURIs: []string{"https://a2.example.com/cb"}, TokenFormat: "jwt"},
		{ClientID: "b1", NamespaceID: "tenant-b", SectorID: "b1", RedirectURIs: []string{"https://b1.example.com/cb"}, TokenFormat: "jwt"},
	} {
		if _, err := store.Create(ctx, c); err != nil {
			t.Fatalf("Create(%s): %v", c.ClientID, err)
		}
	}

	if err := store.SoftDeleteAllForNamespace(ctx, "tenant-a"); err != nil {
		t.Fatalf("SoftDeleteAllForNamespace: %v", err)
	}

	if _, err := store.Get(ctx, "a1", "tenant-a"); !errors.Is(err, ErrClientNotFound) {
		t.Errorf("Get(a1) after namespace cascade delete error = %v, want ErrClientNotFound", err)
	}
	if _, err := store.Get(ctx, "a2", "tenant-a"); !errors.Is(err, ErrClientNotFound) {
		t.Errorf("Get(a2) after namespace cascade delete error = %v, want ErrClientNotFound", err)
	}
	// tenant-b's client must be completely unaffected by tenant-a's cascade.
	if _, err := store.Get(ctx, "b1", "tenant-b"); err != nil {
		t.Errorf("Get(b1) after tenant-a's cascade delete: %v, want still live", err)
	}
}

func TestDBNamespacedClientStoreSoftDeleteAllForNamespaceOfEmptyNamespaceIsNoOp(t *testing.T) {
	store, _ := newTestNamespacedClientStore()
	if err := store.SoftDeleteAllForNamespace(context.Background(), "never-had-clients"); err != nil {
		t.Fatalf("SoftDeleteAllForNamespace() on a namespace with no clients error = %v, want nil", err)
	}
}

func TestDBNamespacedClientStoreListScopedToNamespace(t *testing.T) {
	store, _ := newTestNamespacedClientStore()
	ctx := context.Background()
	for _, c := range []NewNamespacedClient{
		{ClientID: "a1", NamespaceID: "tenant-a", SectorID: "a1", RedirectURIs: []string{"https://a1.example.com/cb"}, TokenFormat: "jwt"},
		{ClientID: "a2", NamespaceID: "tenant-a", SectorID: "a2", RedirectURIs: []string{"https://a2.example.com/cb"}, TokenFormat: "jwt"},
		{ClientID: "b1", NamespaceID: "tenant-b", SectorID: "b1", RedirectURIs: []string{"https://b1.example.com/cb"}, TokenFormat: "jwt"},
	} {
		if _, err := store.Create(ctx, c); err != nil {
			t.Fatalf("Create(%s): %v", c.ClientID, err)
		}
	}

	listA, err := store.List(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listA) != 2 {
		t.Fatalf("List(tenant-a) returned %d clients, want 2", len(listA))
	}
}
