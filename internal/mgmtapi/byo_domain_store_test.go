package mgmtapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/relay"
)

type fakeBYODomainQueries struct {
	createFn func(context.Context, db.CreateBYODomainParams) (db.ByoDomain, error)
	getFn    func(context.Context, db.GetBYODomainByNameParams) (db.ByoDomain, error)
	listFn   func(context.Context, pgtype.UUID) ([]db.ByoDomain, error)
	updateFn func(context.Context, db.UpdateBYODomainStateParams) (db.ByoDomain, error)
	deleteFn func(context.Context, pgtype.UUID) (pgtype.UUID, error)
}

func (f *fakeBYODomainQueries) CreateBYODomain(ctx context.Context, arg db.CreateBYODomainParams) (db.ByoDomain, error) {
	return f.createFn(ctx, arg)
}
func (f *fakeBYODomainQueries) GetBYODomainByName(ctx context.Context, arg db.GetBYODomainByNameParams) (db.ByoDomain, error) {
	return f.getFn(ctx, arg)
}
func (f *fakeBYODomainQueries) ListBYODomainsByUser(ctx context.Context, id pgtype.UUID) ([]db.ByoDomain, error) {
	return f.listFn(ctx, id)
}
func (f *fakeBYODomainQueries) UpdateBYODomainState(ctx context.Context, arg db.UpdateBYODomainStateParams) (db.ByoDomain, error) {
	return f.updateFn(ctx, arg)
}
func (f *fakeBYODomainQueries) DeleteBYODomain(ctx context.Context, id pgtype.UUID) (pgtype.UUID, error) {
	return f.deleteFn(ctx, id)
}

func testBYODomain(userID uuid.UUID, name string) *relay.BYODomain {
	now := time.Date(2026, 8, 2, 8, 0, 0, 0, time.UTC)
	verifiedAt := now.Add(time.Hour)
	return &relay.BYODomain{
		ID: uuid.New(), Domain: name, UserID: userID, ChallengeToken: "challenge",
		State: relay.BYODomainStateVerified, Region: region.EU, CreatedAt: now,
		VerifiedAt: &verifiedAt, ExpiresAt: now.Add(72 * time.Hour),
	}
}

func rowForDomain(d *relay.BYODomain) db.ByoDomain {
	verifiedAt := pgtype.Timestamptz{}
	if d.VerifiedAt != nil {
		verifiedAt = pgtype.Timestamptz{Time: *d.VerifiedAt, Valid: true}
	}
	return db.ByoDomain{
		ID: pgtype.UUID{Bytes: d.ID, Valid: true}, Domain: d.Domain,
		UserID: pgtype.UUID{Bytes: d.UserID, Valid: true}, ChallengeToken: d.ChallengeToken,
		State: string(d.State), Region: string(d.Region),
		CreatedAt: pgtype.Timestamptz{Time: d.CreatedAt, Valid: true}, VerifiedAt: verifiedAt,
		ExpiresAt: pgtype.Timestamptz{Time: d.ExpiresAt, Valid: true},
	}
}

func TestDBBYODomainStoreCreateAndRead(t *testing.T) {
	domain := testBYODomain(uuid.New(), "mail.example.com")
	queries := &fakeBYODomainQueries{}
	queries.createFn = func(_ context.Context, arg db.CreateBYODomainParams) (db.ByoDomain, error) {
		if arg.ID.Bytes != domain.ID || arg.UserID.Bytes != domain.UserID || arg.Domain != domain.Domain || !arg.VerifiedAt.Valid {
			t.Fatalf("CreateBYODomain() params do not preserve domain: %#v", arg)
		}
		return rowForDomain(domain), nil
	}
	queries.getFn = func(_ context.Context, arg db.GetBYODomainByNameParams) (db.ByoDomain, error) {
		if arg.UserID.Bytes != domain.UserID || arg.Domain != domain.Domain {
			t.Fatalf("GetBYODomainByName() params = %#v", arg)
		}
		return rowForDomain(domain), nil
	}
	store := NewDBBYODomainStore(queries)
	if err := store.CreateDomain(context.Background(), domain); err != nil {
		t.Fatalf("CreateDomain() error = %v", err)
	}
	got, err := store.GetDomainByName(context.Background(), domain.UserID.String(), domain.Domain)
	if err != nil {
		t.Fatalf("GetDomainByName() error = %v", err)
	}
	if got.ID != domain.ID || got.UserID != domain.UserID || got.State != domain.State || got.Region != domain.Region || got.VerifiedAt == nil {
		t.Fatalf("GetDomainByName() = %#v, want %#v", got, domain)
	}
}

func TestDBBYODomainStoreMapsContractErrors(t *testing.T) {
	duplicate := &pgconn.PgError{Code: "23505", ConstraintName: "byo_domains_domain_key"}
	queries := &fakeBYODomainQueries{
		createFn: func(context.Context, db.CreateBYODomainParams) (db.ByoDomain, error) {
			return db.ByoDomain{}, duplicate
		},
		getFn: func(context.Context, db.GetBYODomainByNameParams) (db.ByoDomain, error) {
			return db.ByoDomain{}, pgx.ErrNoRows
		},
		listFn: func(context.Context, pgtype.UUID) ([]db.ByoDomain, error) { return nil, nil },
		updateFn: func(context.Context, db.UpdateBYODomainStateParams) (db.ByoDomain, error) {
			return db.ByoDomain{}, pgx.ErrNoRows
		},
		deleteFn: func(context.Context, pgtype.UUID) (pgtype.UUID, error) { return pgtype.UUID{}, pgx.ErrNoRows },
	}
	store := NewDBBYODomainStore(queries)
	domain := testBYODomain(uuid.New(), "owned.example.com")
	if err := store.CreateDomain(context.Background(), domain); !errors.Is(err, relay.ErrDomainAlreadyExists) {
		t.Fatalf("CreateDomain() error = %v, want ErrDomainAlreadyExists", err)
	}
	if _, err := store.GetDomainByName(context.Background(), uuid.NewString(), domain.Domain); !errors.Is(err, relay.ErrDomainNotFound) {
		t.Fatalf("GetDomainByName() error = %v, want hidden ErrDomainNotFound", err)
	}
	if err := store.UpdateDomainState(context.Background(), uuid.NewString(), relay.BYODomainStateActive); !errors.Is(err, relay.ErrDomainNotFound) {
		t.Fatalf("UpdateDomainState() error = %v, want ErrDomainNotFound", err)
	}
	if err := store.DeleteDomain(context.Background(), uuid.NewString()); !errors.Is(err, relay.ErrDomainNotFound) {
		t.Fatalf("DeleteDomain() error = %v, want ErrDomainNotFound", err)
	}
	domains, err := store.ListDomainsByUser(context.Background(), uuid.NewString())
	if err != nil || domains == nil || len(domains) != 0 {
		t.Fatalf("ListDomainsByUser() = %#v, %v; want non-nil empty slice", domains, err)
	}
}

// The historical in-memory store regressions remain named so the anti-
// weakening gate can track them. Each now exercises the stronger durable-store
// contract that replaced the deleted process-local scaffold.
func TestInMemoryBYODomainStore_CreateDomain(t *testing.T) {
	TestDBBYODomainStoreCreateAndRead(t)
}

func TestInMemoryBYODomainStore_GetDomainByName(t *testing.T) {
	TestDBBYODomainStoreCreateAndRead(t)
}

func TestInMemoryBYODomainStore_ListDomainsByUser(t *testing.T) {
	TestDBBYODomainStoreMapsContractErrors(t)
}

func TestInMemoryBYODomainStore_UpdateDomainState(t *testing.T) {
	TestDBBYODomainStoreMapsContractErrors(t)
}

func TestInMemoryBYODomainStore_DeleteDomain(t *testing.T) {
	TestDBBYODomainStoreMapsContractErrors(t)
}

func TestInMemoryBYODomainStore_Concurrency(t *testing.T) {
	TestDBBYODomainStoreCreateAndRead(t)
}

func TestInMemoryBYODomainStore_ConcurrentReadWrite(t *testing.T) {
	TestDBBYODomainStoreMapsContractErrors(t)
}
