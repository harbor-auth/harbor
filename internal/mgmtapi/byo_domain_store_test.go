package mgmtapi

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

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

func TestDBBYODomainStorePersistsAcrossInstances(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is required for PostgreSQL persistence coverage")
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "byo_store_" + uuid.NewString()
	schema = "\"" + schema + "\""
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, dropErr := admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); dropErr != nil {
			t.Errorf("drop test schema: %v", dropErr)
		}
	}()
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, `
		CREATE TABLE users (id uuid PRIMARY KEY);
		CREATE TABLE byo_domains (
			id uuid PRIMARY KEY, domain text NOT NULL UNIQUE,
			user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			challenge_token text NOT NULL, state text NOT NULL CHECK (state IN ('pending','verified','active','failed')),
			region text NOT NULL, created_at timestamptz NOT NULL, verified_at timestamptz, expires_at timestamptz NOT NULL
		)`)
	if err != nil {
		t.Fatal(err)
	}
	userA, userB := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO users(id) VALUES ($1), ($2)", userA, userB); err != nil {
		t.Fatal(err)
	}
	domain := testBYODomain(userA, "persist.example.com")
	domain.State, domain.VerifiedAt = relay.BYODomainStatePending, nil
	if err := NewDBBYODomainStore(db.New(pool)).CreateDomain(ctx, domain); err != nil {
		t.Fatal(err)
	}
	second := NewDBBYODomainStore(db.New(pool))
	if _, err := second.GetDomainByName(ctx, userB.String(), domain.Domain); !errors.Is(err, relay.ErrDomainNotFound) {
		t.Fatalf("cross-owner read = %v", err)
	}
	duplicate := testBYODomain(userB, domain.Domain)
	if err := second.CreateDomain(ctx, duplicate); !errors.Is(err, relay.ErrDomainAlreadyExists) {
		t.Fatalf("duplicate create = %v", err)
	}
	if err := second.UpdateDomainState(ctx, domain.ID.String(), relay.BYODomainStateVerified); err != nil {
		t.Fatal(err)
	}
	got, err := NewDBBYODomainStore(db.New(pool)).GetDomainByName(ctx, userA.String(), domain.Domain)
	if err != nil || got.State != relay.BYODomainStateVerified || got.VerifiedAt == nil {
		t.Fatalf("persisted transition = %#v, %v", got, err)
	}
	if err := second.DeleteDomain(ctx, domain.ID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDBBYODomainStore(db.New(pool)).GetDomainByName(ctx, userA.String(), domain.Domain); !errors.Is(err, relay.ErrDomainNotFound) {
		t.Fatalf("read after delete = %v", err)
	}
}
