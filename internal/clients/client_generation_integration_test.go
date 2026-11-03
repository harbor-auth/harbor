//go:build integration

package clients_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/cloudapi"
	db "github.com/harbor-auth/harbor/internal/gen/db"
	cloudopenapi "github.com/harbor-auth/harbor/internal/gen/openapi/cloud"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Boundary: real PostgreSQL migrations, locking, generation fence, store and
// trigger enforcement. No database or mutation implementation is mocked.
func generationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL is required for generation ordering tests")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "client_generation_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(t.Context(), "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
		admin.Close()
	})
	for _, name := range []string{"0001_init.up.sql", "0012_client_registration.up.sql", "0017_logout_uris.up.sql", "0019_cloud_namespaces.up.sql", "0020_relying_parties_namespace.up.sql", "0025_cloud_client_generation.up.sql"} {
		raw, e := os.ReadFile(filepath.Join("../../db/migrations", name))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Exec(t.Context(), string(raw)); e != nil {
			t.Fatalf("migration %s: %v", name, e)
		}
	}
	if _, err = pool.Exec(t.Context(), "INSERT INTO cloud_namespaces(id,status) VALUES ('tenant-a','active'),('tenant-b','active')"); err != nil {
		t.Fatal(err)
	}
	return pool
}
func generationConfiguration(callback, hash string) clients.ClientConfiguration {
	method := "none"
	if hash != "" {
		method = "client_secret_basic"
	}
	return clients.ClientConfiguration{Name: "", RedirectURIs: []string{callback}, ScopesAllowed: []string{"openid"}, SecretHash: hash, GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, AuthMethod: method}
}
func generationMutation(id string, generation int64, cfg clients.ClientConfiguration) clients.VersionedClientMutation {
	return clients.VersionedClientMutation{Action: "upsert", NamespaceID: "tenant-a", ClientID: id, Generation: generation, Configuration: cfg}
}

func TestGenerationOrderingAndTerminalDeletion(t *testing.T) {
	pool := generationPool(t)
	store := clients.NewDBNamespacedClientStore(db.New(pool))
	ctx := t.Context()
	old := generationMutation("generation-client", 1, generationConfiguration("https://old.example/cb", strings.Repeat("a", 64)))
	first, err := store.ApplyVersioned(ctx, old)
	if err != nil {
		t.Fatal(err)
	}
	if first.Generation != 1 || first.NamespaceID != "tenant-a" {
		t.Fatal("generation response missing identity")
	}
	var before string
	if err = pool.QueryRow(ctx, "SELECT xmin::text FROM relying_parties WHERE client_id=$1", old.ClientID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	retry := old
	retry.Action = "update"
	if _, err = store.ApplyVersioned(ctx, retry); err != nil {
		t.Fatal("same-generation method-independent retry failed", err)
	}
	var after string
	if err := pool.QueryRow(ctx, "SELECT xmin::text FROM relying_parties WHERE client_id=$1", old.ClientID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("equal generation retry rewrote state")
	}
	conflict := old
	conflict.Configuration.RedirectURIs = []string{"https://different.example/cb"}
	if _, err = store.ApplyVersioned(ctx, conflict); !errors.Is(err, clients.ErrClientGenerationConflict) {
		t.Fatal("same-generation drift accepted", err)
	}
	newer := generationMutation(old.ClientID, 3, generationConfiguration("https://new.example/cb", strings.Repeat("b", 64)))
	if _, err = store.ApplyVersioned(ctx, newer); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ApplyVersioned(ctx, old); !errors.Is(err, clients.ErrStaleClientGeneration) {
		t.Fatal("late secret/callback state accepted", err)
	}
	deletion := old
	deletion.Action = "delete"
	deletion.Generation = 2
	if _, err = store.ApplyVersioned(ctx, deletion); !errors.Is(err, clients.ErrStaleClientGeneration) {
		t.Fatal("stale deletion accepted", err)
	}
	current, err := store.Get(ctx, old.ClientID, "tenant-a")
	if err != nil || current.Generation != 3 || current.RedirectURIs[0] != "https://new.example/cb" {
		t.Fatal("stale write changed current state", err)
	}
	deletion.Generation = 4
	if _, err = store.ApplyVersioned(ctx, deletion); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ApplyVersioned(ctx, deletion); err != nil {
		t.Fatal("identical terminal retry failed", err)
	}
	newer.Generation = 5
	if _, err = store.ApplyVersioned(ctx, newer); !errors.Is(err, clients.ErrClientGenerationConflict) {
		t.Fatal("deleted client resurrected", err)
	}
	for _, query := range []string{
		"UPDATE relying_parties SET name='unversioned overwrite' WHERE client_id='generation-client'",
		"DELETE FROM relying_parties WHERE client_id='generation-client'",
		"INSERT INTO relying_parties(client_id,name,sector_id,token_format) VALUES('generation-client','bootstrap overwrite','generation-client','jwt') ON CONFLICT(client_id) DO UPDATE SET name=EXCLUDED.name",
	} {
		if _, err = pool.Exec(ctx, query); err == nil {
			t.Fatal("generic mutation bypassed generation fence")
		}
	}
}

func TestGenerationDeleteBeforeCreateAndNamespaceCascade(t *testing.T) {
	pool := generationPool(t)
	store := clients.NewDBNamespacedClientStore(db.New(pool))
	ctx := t.Context()
	deletion := generationMutation("never-created-client", 2, generationConfiguration("https://example.com/cb", ""))
	deletion.Action = "delete"
	if _, err := store.ApplyVersioned(ctx, deletion); err != nil {
		t.Fatal(err)
	}
	for _, gen := range []int64{1, 3} {
		create := deletion
		create.Action = "upsert"
		create.Generation = gen
		_, err := store.ApplyVersioned(ctx, create)
		if gen == 1 && !errors.Is(err, clients.ErrStaleClientGeneration) {
			t.Fatal("delayed create passed tombstone", err)
		}
		if gen == 3 && !errors.Is(err, clients.ErrClientGenerationConflict) {
			t.Fatal("higher create resurrected tombstone", err)
		}
	}
	if _, err := pool.Exec(ctx, "INSERT INTO relying_parties(client_id,namespace_id,name,sector_id,token_format) VALUES('never-created-client','tenant-a','bad','bad','jwt')"); err == nil {
		t.Fatal("delayed unversioned insert bypassed tombstone")
	}
	live := generationMutation("namespace-client", 1, generationConfiguration("https://example.com/cb", ""))
	if _, err := store.ApplyVersioned(ctx, live); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE cloud_namespaces SET deleted_at=now() WHERE id='tenant-a'"); err != nil {
		t.Fatal(err)
	}
	if err := store.SoftDeleteAllForNamespace(ctx, "tenant-a"); err != nil {
		t.Fatal("namespace terminal cascade blocked", err)
	}
	live.Generation = 2
	if _, err := store.ApplyVersioned(ctx, live); !errors.Is(err, clients.ErrNamespaceInactive) {
		t.Fatal("deleted namespace accepted client", err)
	}
	rollback, err := os.ReadFile("../../db/migrations/0025_cloud_client_generation.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(rollback)); err == nil {
		t.Fatal("rollback discarded security fences")
	}
}

func TestForeignDeleteFencesOnlyItsOwnNamespace(t *testing.T) {
	pool := generationPool(t)
	store := clients.NewDBNamespacedClientStore(db.New(pool))
	ctx := t.Context()
	if _, err := pool.Exec(ctx, "INSERT INTO relying_parties(client_id,namespace_id,name,sector_id,token_format) VALUES('foreign-unmanaged','tenant-b','owner','sector','jwt')"); err != nil {
		t.Fatal(err)
	}
	deletion := generationMutation("foreign-unmanaged", 2, generationConfiguration("https://example.com/cb", ""))
	deletion.Action = "delete"
	if _, err := store.ApplyVersioned(ctx, deletion); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE relying_parties SET name='owner updated' WHERE client_id='foreign-unmanaged'"); err != nil {
		t.Fatal("foreign namespace fence blocked owner", err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM relying_parties WHERE client_id='foreign-unmanaged'"); err != nil {
		t.Fatal(err)
	}
	deletion.Action = "upsert"
	deletion.Generation = 1
	if _, err := store.ApplyVersioned(ctx, deletion); !errors.Is(err, clients.ErrStaleClientGeneration) {
		t.Fatal("foreign delete failed to retain requesting namespace tombstone", err)
	}
	owner := generationMutation("foreign-versioned", 1, generationConfiguration("https://owner.example/cb", ""))
	owner.NamespaceID = "tenant-b"
	if _, err := store.ApplyVersioned(ctx, owner); err != nil {
		t.Fatal(err)
	}
	deletion.ClientID = owner.ClientID
	deletion.Action = "delete"
	deletion.Generation = 100
	if _, err := store.ApplyVersioned(ctx, deletion); err != nil {
		t.Fatal(err)
	}
	owner.Generation = 2
	if _, err := store.ApplyVersioned(ctx, owner); err != nil {
		t.Fatal("foreign delete blocked owner's next generation", err)
	}
}

func TestConcurrentLateGenerationCannotOverwriteCommittedNewerConfiguration(t *testing.T) {
	pool := generationPool(t)
	store := clients.NewDBNamespacedClientStore(db.New(pool))
	ctx := t.Context()
	initial := generationMutation("concurrent-client", 1, generationConfiguration("https://first.example/cb", ""))
	if _, err := store.ApplyVersioned(ctx, initial); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Rollback(context.Background()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Errorf("rollback test transaction: %v", err)
		}
	}()
	newest := initial
	newest.Generation = 3
	newest.Configuration.RedirectURIs = []string{"https://latest.example/cb"}
	if _, err = clients.NewDBNamespacedClientStore(db.New(tx)).ApplyVersioned(ctx, newest); err != nil {
		t.Fatal(err)
	}
	late := initial
	late.Generation = 2
	done := make(chan error, 1)
	go func() { _, err := store.ApplyVersioned(ctx, late); done <- err }()
	deadline := time.Now().Add(3 * time.Second)
	blocked := false
	for time.Now().Before(deadline) {
		var n int
		if err = pool.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE wait_event='advisory'").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			blocked = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("late write never reached PostgreSQL generation lock")
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if !errors.Is(err, clients.ErrStaleClientGeneration) {
			t.Fatal("late write accepted", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("late writer did not finish")
	}
	got, err := store.Get(ctx, initial.ClientID, "tenant-a")
	if err != nil || got.Generation != 3 || got.RedirectURIs[0] != "https://latest.example/cb" {
		t.Fatal("late write replaced latest configuration", err)
	}
}

func TestPartialMetadataUpdateCannotUndoConcurrentSecretRotation(t *testing.T) {
	pool := generationPool(t)
	store := clients.NewDBNamespacedClientStore(db.New(pool))
	ctx := t.Context()
	initial := generationMutation("partial-cas-client", 1, generationConfiguration("https://old.example/cb", strings.Repeat("a", 64)))
	if _, err := store.ApplyVersioned(ctx, initial); err != nil {
		t.Fatal(err)
	}
	staleBase := int64(1)
	partial := initial
	partial.Action = "update"
	partial.Generation = 3
	partial.ExpectedBase = &staleBase
	partial.Configuration.RedirectURIs = []string{"https://callback-update.example/cb"}
	rotation := initial
	rotation.Generation = 2
	rotation.Configuration.SecretHash = strings.Repeat("b", 64)
	if _, err := store.ApplyVersioned(ctx, rotation); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyVersioned(ctx, partial); !errors.Is(err, clients.ErrStaleClientGeneration) {
		t.Fatal("partial callback update overwrote concurrent secret rotation", err)
	}
	current, err := store.Get(ctx, initial.ClientID, "tenant-a")
	if err != nil || current.Generation != 2 || hex.EncodeToString(current.ClientSecretHash) != rotation.Configuration.SecretHash {
		t.Fatal("partial metadata update lost a rotated secret", err)
	}
	currentBase := int64(2)
	partial.ExpectedBase = &currentBase
	partial.Configuration.SecretHash = rotation.Configuration.SecretHash
	if _, err := store.ApplyVersioned(ctx, partial); err != nil {
		t.Fatal("rebased partial update failed", err)
	}
	// Equal-generation identical retries ignore stale read-base metadata because
	// it is not part of desired state and must not turn an ACK into a rewrite.
	partial.ExpectedBase = &staleBase
	if _, err := store.ApplyVersioned(ctx, partial); err != nil {
		t.Fatal("identical retry rejected stale observation metadata", err)
	}
}

func TestConfigurationAPIRequiresGenerationAndNeverAcknowledgesStaleLedger(t *testing.T) {
	pool := generationPool(t)
	q := db.New(pool)
	server := cloudapi.NewServer(cloudapi.NewStore(q), clients.NewDBNamespacedClientStore(q))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			server.DeleteAdminV1NamespacesClientConfiguration(w, r, "tenant-a", "api-versioned-client", cloudopenapi.DeleteAdminV1NamespacesClientConfigurationParams{IdempotencyKey: r.Header.Get("Idempotency-Key")})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/configuration") {
			server.PutAdminV1NamespacesClientConfiguration(w, r, "tenant-a", "api-versioned-client", cloudopenapi.PutAdminV1NamespacesClientConfigurationParams{IdempotencyKey: r.Header.Get("Idempotency-Key")})
			return
		}
		server.PutAdminV1NamespacesClient(w, r, "tenant-a", "api-versioned-client", cloudopenapi.PutAdminV1NamespacesClientParams{IdempotencyKey: r.Header.Get("Idempotency-Key")})
	})
	path := "/admin/v1/namespaces/tenant-a/clients/api-versioned-client/configuration"
	send := func(method, path, key, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Idempotency-Key", key)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	firstBody := `{"generation":1,"redirect_uris":["https://old.example/cb"],"token_endpoint_auth_method":"none"}`
	first := send("PUT", path, "api-gen-1", firstBody)
	if first.Code != 200 || first.Header().Get("X-Harbor-Generation") != "1" {
		t.Fatalf("initial upsert failed %d %s", first.Code, first.Body.String())
	}
	var result cloudopenapi.ClientResponse
	if err := json.Unmarshal(first.Body.Bytes(), &result); err != nil || result.Generation != 1 || result.NamespaceId != "tenant-a" || result.ClientId != "api-versioned-client" {
		t.Fatal("missing receiver capability/identity ACK", err)
	}
	next := send("PUT", path, "api-gen-2", `{"generation":2,"redirect_uris":["https://new.example/cb"],"token_endpoint_auth_method":"none"}`)
	if next.Code != 200 || next.Header().Get("X-Harbor-Generation") != "2" {
		t.Fatal("next generation failed")
	}
	for _, oldPath := range []string{path, strings.TrimSuffix(path, "/configuration")} {
		stale := send("PUT", oldPath, "api-gen-1", firstBody)
		if stale.Code != 409 || !strings.Contains(stale.Body.String(), "stale_generation") || stale.Header().Get("X-Harbor-Generation") != "" {
			t.Fatalf("cached ledger bypassed generation fence: %d %s", stale.Code, stale.Body.String())
		}
	}
	for _, badGen := range []string{"", `"generation":0,`, `"generation":-1,`} {
		bad := send("PUT", path, "invalid-gen", `{`+badGen+`"redirect_uris":["https://new.example/cb"],"token_endpoint_auth_method":"none"}`)
		if bad.Code != 400 || bad.Header().Get("X-Harbor-Generation") != "" {
			t.Fatal("invalid generation accepted")
		}
	}
	deleted := send("DELETE", path+"?generation=3", "api-del-3", "")
	if deleted.Code != 204 || deleted.Header().Get("X-Harbor-Generation") != "3" {
		t.Fatal("deletion missing receiver ACK")
	}
	replay := send("DELETE", path+"?generation=3", "api-del-3", "")
	if replay.Code != 204 || replay.Header().Get("X-Harbor-Generation") != "3" {
		t.Fatal("deletion replay lost generation ACK")
	}
	resurrection := send("PUT", path, "resurrection-4", `{"generation":4,"redirect_uris":["https://new.example/cb"],"token_endpoint_auth_method":"none"}`)
	if resurrection.Code != 409 {
		t.Fatal("terminal deletion resurrected")
	}
}
