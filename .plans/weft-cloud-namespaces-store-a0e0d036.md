# Cloud namespaces/operations/sessions migration + domain model (Task 2)

1. Read the openspec change (`proposal.md`, `design.md`, `spec.md`, `tasks.md`) for
   `harbor-cloud-management-api-contract-2ee993ea` to pin down the exact schema:
   `cloud_namespaces(id text pk, status, created_at, updated_at, deleted_at)`,
   `cloud_operations(idempotency_key, operation, request_hash, response_body jsonb,
   created_at, pk(idempotency_key, operation))`, `cloud_sessions(session_id text pk,
   namespace_id references cloud_namespaces(id), token_hash, expires_at, consumed_at,
   created_at)`.
2. Add `db/migrations/0019_cloud_namespaces.{up,down}.sql` following the greenfield
   CREATE pattern used by 0008/0016 (fail-fast lock/statement timeouts, no CONCURRENTLY
   needed for new tables).
3. Add `db/queries/cloud_{namespaces,operations,sessions}.sql` (Create/Get for all
   three, plus SoftDelete for namespaces) and regenerate with `sqlc generate`
   (pin to the repo's v1.30.0 to avoid version-comment noise in unrelated files).
4. Add `internal/cloudapi/store.go`: a `Store` wrapping a narrow `querier` interface
   over the generated `*db.Queries`, with domain types (`Namespace`, `Operation`,
   `Session`) and Create/Get/SoftDelete methods that map `pgx.ErrNoRows` /
   unique-violation errors to sentinel errors, mirroring `internal/clients` and
   `internal/mgmtapi/byo_domain_store.go` conventions. Lifecycle interpretation
   (soft-delete-as-404, expiry, cross-tenant) is left to later handler tasks — the
   store returns raw state.
5. Add `internal/cloudapi/store_test.go` with a function-field fake querier
   (byo_domain_store_test.go style) covering create/get/soft-delete happy paths and
   error-mapping (not-found, already-exists) for all three record types.
6. Verify: `gofmt -l`, `go build ./...`, `go vet ./...`, `go test ./...`,
   `sqlc generate` produces no drift beyond the intended new files.
7. Commit and push.
