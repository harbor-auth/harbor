//go:build integration

package clients_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/cloudapi"
	db "github.com/harbor-auth/harbor/internal/gen/db"
	cloudopenapi "github.com/harbor-auth/harbor/internal/gen/openapi/cloud"
	"github.com/jackc/pgx/v5"
)

const atomicClientBody = `{"generation":1,"redirect_uris":["https://app.example/callback"],"token_endpoint_auth_method":"none"}`

// Boundary: real HTTP client-configuration handler, SQL store, generation
// function and durable ledger. The test controls only PostgreSQL lock ordering.
func TestClientOperationConcurrentKeyCannotMutateTwoClients(t *testing.T) {
	pool := generationPool(t)
	q := db.New(pool)
	server := cloudapi.NewServer(cloudapi.NewStore(q), clients.NewDBNamespacedClientStore(q))
	send := func(id string) *httptest.ResponseRecorder {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req := httptest.NewRequest(http.MethodPut, "/configuration", strings.NewReader(atomicClientBody)).WithContext(ctx)
		rec := httptest.NewRecorder()
		server.PutAdminV1NamespacesClientConfiguration(rec, req, "tenant-a", id, cloudopenapi.PutAdminV1NamespacesClientConfigurationParams{IdempotencyKey: "concurrent-operation-key"})
		return rec
	}
	blocker, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := blocker.Rollback(context.Background()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error(err)
		}
	}()
	if _, err = blocker.Exec(t.Context(), `SELECT pg_advisory_xact_lock(hashtextextended('atomic-client-first',294351))`); err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { firstDone <- send("atomic-client-first") }()
	// Observe the first request's granted operation lock without acquiring it:
	// competing for this nonblocking lock could make the request itself fail.
	// The mutation remains held behind the client lock until we release blocker.
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case first := <-firstDone:
			t.Fatalf("first request returned before reserving its blocked mutation: %d %s", first.Code, first.Body.String())
		default:
		}
		var reserved bool
		err = pool.QueryRow(t.Context(), `
			WITH operation_key AS (
			 SELECT hashtextextended(jsonb_build_array('concurrent-operation-key'::text,'client.update'::text)::text,294352) AS value
			)
			SELECT EXISTS (
			 SELECT 1 FROM pg_locks, operation_key
			 WHERE locktype='advisory' AND granted AND objsubid=1
			 AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
			 AND classid=((operation_key.value >> 32) & 4294967295)::oid
			 AND objid=(operation_key.value & 4294967295)::oid
			)`).Scan(&reserved)
		if err != nil {
			t.Fatal(err)
		}
		if reserved {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first request did not reserve operation key")
		}
		time.Sleep(time.Millisecond)
	}
	competing := send("atomic-client-second")
	if competing.Code != 409 || !strings.Contains(competing.Body.String(), "operation_in_progress") || competing.Header().Get("X-Harbor-Generation") != "" {
		t.Fatalf("competing write was acknowledged: %d %s", competing.Code, competing.Body.String())
	}
	if err = blocker.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	first := <-firstDone
	if first.Code != 200 {
		t.Fatalf("first write: %d %s", first.Code, first.Body.String())
	}
	conflicting := send("atomic-client-second")
	if conflicting.Code != 409 || !strings.Contains(conflicting.Body.String(), "idempotency_key_reused") {
		t.Fatalf("conflicting retry: %d %s", conflicting.Code, conflicting.Body.String())
	}
	replay := send("atomic-client-first")
	if replay.Code != 200 || replay.Body.String() != first.Body.String() || replay.Header().Get("X-Harbor-Generation") != "1" {
		t.Fatalf("identical retry: %d %s", replay.Code, replay.Body.String())
	}
	var rows, receipts int
	if err = pool.QueryRow(t.Context(), `SELECT count(*) FROM relying_parties WHERE client_id IN ('atomic-client-first','atomic-client-second')`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(t.Context(), `SELECT count(*) FROM cloud_operations WHERE idempotency_key='concurrent-operation-key'`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || receipts != 1 {
		t.Fatalf("rows=%d receipts=%d; want one atomic accepted operation", rows, receipts)
	}
}

func TestClientOperationLedgerFailureRollsBackMutationAndFence(t *testing.T) {
	pool := generationPool(t)
	q := db.New(pool)
	server := cloudapi.NewServer(cloudapi.NewStore(q), clients.NewDBNamespacedClientStore(q))
	if _, err := pool.Exec(t.Context(), `CREATE FUNCTION reject_test_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test ledger unavailable'; END $$; CREATE TRIGGER test_receipt_failure BEFORE INSERT ON cloud_operations FOR EACH ROW EXECUTE FUNCTION reject_test_receipt()`); err != nil {
		t.Fatal(err)
	}
	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("PUT", "/configuration", strings.NewReader(atomicClientBody))
		rec := httptest.NewRecorder()
		server.PutAdminV1NamespacesClientConfiguration(rec, req, "tenant-a", "atomic-client-rollback", cloudopenapi.PutAdminV1NamespacesClientConfigurationParams{IdempotencyKey: "receipt-failure-key"})
		return rec
	}
	failed := send()
	if failed.Code != 500 || failed.Header().Get("X-Harbor-Generation") != "" {
		t.Fatalf("unrecorded mutation acknowledged: %d %s", failed.Code, failed.Body.String())
	}
	for _, table := range []string{"relying_parties", "cloud_client_versions", "cloud_operations"} {
		var count int
		if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s retained %d rows after failed receipt", table, count)
		}
	}
	if _, err := pool.Exec(t.Context(), `DROP TRIGGER test_receipt_failure ON cloud_operations`); err != nil {
		t.Fatal(err)
	}
	if retry := send(); retry.Code != 200 || retry.Header().Get("X-Harbor-Generation") != "1" {
		t.Fatalf("retry after rollback: %d %s", retry.Code, retry.Body.String())
	}
}
