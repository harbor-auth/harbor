package cloudapi

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

// fakeQuerier is a function-field fake satisfying querier, following the
// pattern in internal/mgmtapi/byo_domain_store_test.go: each test wires only
// the methods it exercises.
type fakeQuerier struct {
	createNamespaceFn     func(context.Context, db.CreateCloudNamespaceParams) (db.CloudNamespace, error)
	getNamespaceFn        func(context.Context, string) (db.CloudNamespace, error)
	softDeleteNamespaceFn func(context.Context, string) error
	createOperationFn     func(context.Context, db.CreateCloudOperationParams) (db.CloudOperation, error)
	getOperationFn        func(context.Context, db.GetCloudOperationParams) (db.CloudOperation, error)
	createSessionFn       func(context.Context, db.CreateCloudSessionParams) (db.CloudSession, error)
	getSessionFn          func(context.Context, string) (db.CloudSession, error)
}

func (f *fakeQuerier) CreateCloudNamespace(ctx context.Context, arg db.CreateCloudNamespaceParams) (db.CloudNamespace, error) {
	return f.createNamespaceFn(ctx, arg)
}
func (f *fakeQuerier) GetCloudNamespace(ctx context.Context, id string) (db.CloudNamespace, error) {
	return f.getNamespaceFn(ctx, id)
}
func (f *fakeQuerier) SoftDeleteCloudNamespace(ctx context.Context, id string) error {
	return f.softDeleteNamespaceFn(ctx, id)
}
func (f *fakeQuerier) CreateCloudOperation(ctx context.Context, arg db.CreateCloudOperationParams) (db.CloudOperation, error) {
	return f.createOperationFn(ctx, arg)
}
func (f *fakeQuerier) GetCloudOperation(ctx context.Context, arg db.GetCloudOperationParams) (db.CloudOperation, error) {
	return f.getOperationFn(ctx, arg)
}
func (f *fakeQuerier) CreateCloudSession(ctx context.Context, arg db.CreateCloudSessionParams) (db.CloudSession, error) {
	return f.createSessionFn(ctx, arg)
}
func (f *fakeQuerier) GetCloudSession(ctx context.Context, sessionID string) (db.CloudSession, error) {
	return f.getSessionFn(ctx, sessionID)
}

var errUniqueViolation = &pgconn.PgError{Code: "23505", ConstraintName: "cloud_namespaces_pkey"}

func TestNewStorePanicsOnNilQuerier(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewStore(nil) did not panic")
		}
	}()
	NewStore(nil)
}

func TestStoreCreateAndGetNamespace(t *testing.T) {
	createdAt := pgtype.Timestamptz{Time: time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC), Valid: true}
	q := &fakeQuerier{
		createNamespaceFn: func(_ context.Context, arg db.CreateCloudNamespaceParams) (db.CloudNamespace, error) {
			if arg.ID != "ns-1" || arg.Status != "provisioning" {
				t.Fatalf("CreateCloudNamespace() params = %#v", arg)
			}
			return db.CloudNamespace{ID: arg.ID, Status: arg.Status, CreatedAt: createdAt, UpdatedAt: createdAt}, nil
		},
		getNamespaceFn: func(_ context.Context, id string) (db.CloudNamespace, error) {
			if id != "ns-1" {
				t.Fatalf("GetCloudNamespace() id = %q", id)
			}
			return db.CloudNamespace{ID: id, Status: "provisioning", CreatedAt: createdAt, UpdatedAt: createdAt}, nil
		},
	}
	store := NewStore(q)

	created, err := store.CreateNamespace(context.Background(), "ns-1", "provisioning")
	if err != nil {
		t.Fatalf("CreateNamespace() error = %v", err)
	}
	if created.ID != "ns-1" || created.Status != "provisioning" || created.DeletedAt != nil {
		t.Fatalf("CreateNamespace() = %#v", created)
	}
	if created.CreatedAt.IsZero() {
		t.Fatal("CreateNamespace() CreatedAt not populated")
	}

	got, err := store.GetNamespace(context.Background(), "ns-1")
	if err != nil {
		t.Fatalf("GetNamespace() error = %v", err)
	}
	if got != created {
		t.Fatalf("GetNamespace() = %#v, want %#v", got, created)
	}
}

func TestStoreCreateNamespaceDuplicateID(t *testing.T) {
	q := &fakeQuerier{
		createNamespaceFn: func(context.Context, db.CreateCloudNamespaceParams) (db.CloudNamespace, error) {
			return db.CloudNamespace{}, errUniqueViolation
		},
	}
	store := NewStore(q)
	if _, err := store.CreateNamespace(context.Background(), "ns-1", "provisioning"); !errors.Is(err, ErrNamespaceAlreadyExists) {
		t.Fatalf("CreateNamespace() error = %v, want ErrNamespaceAlreadyExists", err)
	}
}

func TestStoreGetNamespaceNotFound(t *testing.T) {
	q := &fakeQuerier{
		getNamespaceFn: func(context.Context, string) (db.CloudNamespace, error) {
			return db.CloudNamespace{}, pgx.ErrNoRows
		},
	}
	store := NewStore(q)
	if _, err := store.GetNamespace(context.Background(), "missing"); !errors.Is(err, ErrNamespaceNotFound) {
		t.Fatalf("GetNamespace() error = %v, want ErrNamespaceNotFound", err)
	}
}

// GetNamespace must surface a soft-deleted row (not hide it as not-found) so
// the caller — not the store — decides how "deleted" maps to a response.
func TestStoreGetNamespaceReturnsSoftDeletedRow(t *testing.T) {
	deletedAt := pgtype.Timestamptz{Time: time.Date(2026, 8, 3, 13, 0, 0, 0, time.UTC), Valid: true}
	q := &fakeQuerier{
		getNamespaceFn: func(context.Context, string) (db.CloudNamespace, error) {
			return db.CloudNamespace{ID: "ns-1", Status: "deleted", DeletedAt: deletedAt}, nil
		},
	}
	store := NewStore(q)
	got, err := store.GetNamespace(context.Background(), "ns-1")
	if err != nil {
		t.Fatalf("GetNamespace() error = %v", err)
	}
	if got.DeletedAt == nil || !got.DeletedAt.Equal(deletedAt.Time) {
		t.Fatalf("GetNamespace() DeletedAt = %v, want %v", got.DeletedAt, deletedAt.Time)
	}
}

func TestStoreSoftDeleteNamespaceIdempotent(t *testing.T) {
	calls := 0
	q := &fakeQuerier{
		softDeleteNamespaceFn: func(_ context.Context, id string) error {
			calls++
			if id != "ns-1" {
				t.Fatalf("SoftDeleteCloudNamespace() id = %q", id)
			}
			// Mirrors the real UPDATE ... WHERE deleted_at IS NULL: affects
			// zero rows (no error) whether ns-1 never existed or was already
			// deleted by a prior call.
			return nil
		},
	}
	store := NewStore(q)
	for i := 0; i < 2; i++ {
		if err := store.SoftDeleteNamespace(context.Background(), "ns-1"); err != nil {
			t.Fatalf("SoftDeleteNamespace() call %d error = %v", i, err)
		}
	}
	if calls != 2 {
		t.Fatalf("SoftDeleteCloudNamespace() called %d times, want 2", calls)
	}
}

func TestStoreCreateAndGetOperation(t *testing.T) {
	createdAt := pgtype.Timestamptz{Time: time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC), Valid: true}
	requestHash := []byte("request-hash")
	responseBody := []byte(`{"status":201,"body":{"id":"ns-1"}}`)
	q := &fakeQuerier{
		createOperationFn: func(_ context.Context, arg db.CreateCloudOperationParams) (db.CloudOperation, error) {
			if arg.IdempotencyKey != "key-1" || arg.Operation != "namespace.create" {
				t.Fatalf("CreateCloudOperation() params = %#v", arg)
			}
			return db.CloudOperation{
				IdempotencyKey: arg.IdempotencyKey, Operation: arg.Operation,
				RequestHash: arg.RequestHash, ResponseBody: arg.ResponseBody, CreatedAt: createdAt,
			}, nil
		},
		getOperationFn: func(_ context.Context, arg db.GetCloudOperationParams) (db.CloudOperation, error) {
			if arg.IdempotencyKey != "key-1" || arg.Operation != "namespace.create" {
				t.Fatalf("GetCloudOperation() params = %#v", arg)
			}
			return db.CloudOperation{
				IdempotencyKey: arg.IdempotencyKey, Operation: arg.Operation,
				RequestHash: requestHash, ResponseBody: responseBody, CreatedAt: createdAt,
			}, nil
		},
	}
	store := NewStore(q)

	created, err := store.CreateOperation(context.Background(), "key-1", "namespace.create", requestHash, responseBody)
	if err != nil {
		t.Fatalf("CreateOperation() error = %v", err)
	}
	if created.IdempotencyKey != "key-1" || created.Name != "namespace.create" {
		t.Fatalf("CreateOperation() = %#v", created)
	}

	got, err := store.GetOperation(context.Background(), "key-1", "namespace.create")
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if string(got.RequestHash) != string(requestHash) || string(got.ResponseBody) != string(responseBody) {
		t.Fatalf("GetOperation() = %#v", got)
	}
}

func TestStoreCreateOperationAlreadyExists(t *testing.T) {
	q := &fakeQuerier{
		createOperationFn: func(context.Context, db.CreateCloudOperationParams) (db.CloudOperation, error) {
			return db.CloudOperation{}, &pgconn.PgError{Code: "23505", ConstraintName: "cloud_operations_pkey"}
		},
	}
	store := NewStore(q)
	if _, err := store.CreateOperation(context.Background(), "key-1", "namespace.create", nil, nil); !errors.Is(err, ErrOperationAlreadyExists) {
		t.Fatalf("CreateOperation() error = %v, want ErrOperationAlreadyExists", err)
	}
}

func TestStoreGetOperationNotFound(t *testing.T) {
	q := &fakeQuerier{
		getOperationFn: func(context.Context, db.GetCloudOperationParams) (db.CloudOperation, error) {
			return db.CloudOperation{}, pgx.ErrNoRows
		},
	}
	store := NewStore(q)
	if _, err := store.GetOperation(context.Background(), "missing", "namespace.create"); !errors.Is(err, ErrOperationNotFound) {
		t.Fatalf("GetOperation() error = %v, want ErrOperationNotFound", err)
	}
}

func TestStoreCreateAndGetSession(t *testing.T) {
	expiresAt := time.Date(2026, 8, 3, 14, 0, 0, 0, time.UTC)
	tokenHash := []byte("token-hash")
	q := &fakeQuerier{
		createSessionFn: func(_ context.Context, arg db.CreateCloudSessionParams) (db.CloudSession, error) {
			if arg.SessionID != "sess-1" || arg.NamespaceID != "ns-1" || !arg.ExpiresAt.Time.Equal(expiresAt) {
				t.Fatalf("CreateCloudSession() params = %#v", arg)
			}
			return db.CloudSession{
				SessionID: arg.SessionID, NamespaceID: arg.NamespaceID,
				TokenHash: arg.TokenHash, ExpiresAt: arg.ExpiresAt,
			}, nil
		},
		getSessionFn: func(_ context.Context, sessionID string) (db.CloudSession, error) {
			if sessionID != "sess-1" {
				t.Fatalf("GetCloudSession() sessionID = %q", sessionID)
			}
			return db.CloudSession{
				SessionID: sessionID, NamespaceID: "ns-1", TokenHash: tokenHash,
				ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
			}, nil
		},
	}
	store := NewStore(q)

	created, err := store.CreateSession(context.Background(), "sess-1", "ns-1", tokenHash, expiresAt)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if created.SessionID != "sess-1" || created.NamespaceID != "ns-1" || created.ConsumedAt != nil {
		t.Fatalf("CreateSession() = %#v", created)
	}

	got, err := store.GetSession(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if got.NamespaceID != "ns-1" || !got.ExpiresAt.Equal(expiresAt) || string(got.TokenHash) != string(tokenHash) {
		t.Fatalf("GetSession() = %#v", got)
	}
}

func TestStoreGetSessionNotFound(t *testing.T) {
	q := &fakeQuerier{
		getSessionFn: func(context.Context, string) (db.CloudSession, error) {
			return db.CloudSession{}, pgx.ErrNoRows
		},
	}
	store := NewStore(q)
	if _, err := store.GetSession(context.Background(), "missing"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("GetSession() error = %v, want ErrSessionNotFound", err)
	}
}

// A session returned with expires_at in the past or consumed_at set must
// still be handed back — cross_tenant/expiry checks are the caller's job
// (a later task), mirroring GetNamespace's soft-delete behaviour.
func TestStoreGetSessionReturnsExpiredAndConsumedRows(t *testing.T) {
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	consumedAt := pgtype.Timestamptz{Time: past.Add(time.Minute), Valid: true}
	q := &fakeQuerier{
		getSessionFn: func(context.Context, string) (db.CloudSession, error) {
			return db.CloudSession{
				SessionID: "sess-1", NamespaceID: "ns-a",
				ExpiresAt: pgtype.Timestamptz{Time: past, Valid: true}, ConsumedAt: consumedAt,
			}, nil
		},
	}
	store := NewStore(q)
	got, err := store.GetSession(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if !got.ExpiresAt.Equal(past) || got.ConsumedAt == nil || !got.ConsumedAt.Equal(consumedAt.Time) {
		t.Fatalf("GetSession() = %#v", got)
	}
}
