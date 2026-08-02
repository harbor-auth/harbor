//go:build e2e || integration

package mgmtapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/relay"
	"github.com/jackc/pgx/v5/pgxpool"
)

func requiredIntegrationDatabaseURL(t *testing.T) string {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("DATABASE_URL is required for tagged PostgreSQL integration tests")
	}
	return databaseURL
}

func TestDBBYODomainStorePersistsAcrossInstances(t *testing.T) {
	databaseURL := requiredIntegrationDatabaseURL(t)
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := `"byo_store_` + uuid.NewString() + `"`
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
	if err := second.CreateDomain(ctx, testBYODomain(userB, domain.Domain)); !errors.Is(err, relay.ErrDomainAlreadyExists) {
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

func TestIntegrationAuthorizedRegistrationPersistsInPostgres(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), requiredIntegrationDatabaseURL(t))
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	t.Cleanup(pool.Close)

	const iat = "durable-registration-initial-access-token"
	store := clients.NewDBClientRegistrationStore(db.New(pool))
	s := newTestServerWithClient(nil, store).WithInitialAccessToken(iat).RequireRegistrationAuthorization()
	mux := http.NewServeMux()
	s.Routes(mux)
	anon := serveMgmt(t, mux, http.MethodPost, "/register", integrationRegisterBody, "")
	if anon.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous POST /register = %d, want 401; body=%s", anon.Code, anon.Body.String())
	}
	resp := registerClient(t, mux, integrationRegisterBody, bearer(iat))
	t.Cleanup(func() {
		if deleteErr := store.Delete(context.Background(), resp.ClientID); deleteErr != nil {
			t.Errorf("delete registered client: %v", deleteErr)
		}
	})
	persisted, err := clients.NewDBClientRegistrationStore(db.New(pool)).VerifyRegToken(context.Background(), resp.RegistrationAccessToken)
	if err != nil {
		t.Fatalf("fresh PostgreSQL store cannot resolve registration token: %v", err)
	}
	if persisted.ClientID != resp.ClientID {
		t.Fatalf("persisted client_id = %q, want %q", persisted.ClientID, resp.ClientID)
	}
	if len(persisted.ClientSecretHash) == 0 || bytes.Equal(persisted.ClientSecretHash, []byte(resp.ClientSecret)) {
		t.Fatal("durable registration did not persist a non-plaintext client secret hash")
	}
}
