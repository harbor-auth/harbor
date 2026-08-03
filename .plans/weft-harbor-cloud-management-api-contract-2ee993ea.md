# Implement idempotent namespace lifecycle handlers

Task 4 of the harbor-cloud-management-api-contract feature.

1. Read `api/openapi/harbor-cloud.yaml` (namespace paths + `Error`/idempotency
   semantics), `openspec/changes/harbor-cloud-management-api-contract-2ee993ea/design.md`
   §3 and `specs/harbor-cloud-management-api/spec.md`'s namespace-lifecycle
   scenarios, and the generated `internal/gen/openapi/cloud/harbor_cloud.gen.go`
   `ServerInterface` (`PostAdminV1Namespaces`, `GetAdminV1Namespace`,
   `DeleteAdminV1Namespace`) to pin down exact signatures. Cross-check
   `internal/cloudapi/store.go` (`Store.CreateNamespace/GetNamespace/SoftDeleteNamespace`,
   `Store.CreateOperation/GetOperation`) and `internal/oidcapi/admin_keys.go` /
   `internal/mgmtapi/register.go` for handler conventions (body size caps,
   `writeError`-style JSON envelopes, credential/response minting patterns).
2. Add `internal/cloudapi/namespaces.go`:
   - `Server` struct wrapping `*Store` (`NewServer`), the type sibling tasks
     (sessions.go, keys.go) will add more `ServerInterface` methods to.
   - `PostAdminV1Namespaces`: validate `Idempotency-Key` + `id` pattern,
     consult the `cloud_operations` ledger (hash of canonicalized request
     body) — replay verbatim on a hash match, `409 idempotency_key_reused` on
     a mismatch — then `CreateNamespace`, mapping `ErrNamespaceAlreadyExists`
     to `409 namespace_already_exists`. `display_name` has no DB column; it's
     echoed back in the create response only, never persisted.
   - `GetAdminV1Namespace`: `404 namespace_not_found` for both absent and
     soft-deleted rows.
   - `DeleteAdminV1Namespace`: same idempotency-ledger pattern (hashing the
     path `id`, since DELETE has no body), soft-delete via
     `Store.SoftDeleteNamespace`, always `204` — including absent/already-deleted.
   - Shared `storedResponse` JSON envelope (`status` + `body`) persisted in
     `cloud_operations.response_body` so a replay reproduces the original
     response verbatim, plus `writeCloudJSON`/`writeCloudError`/`writeInternalError`
     helpers reused by later cloudapi handler files.
3. Add `internal/cloudapi/namespaces_test.go`: a stateful `memQuerier` fake
   (multi-call sequences needed for retry/duplicate/delete-twice scenarios,
   unlike `store_test.go`'s per-call `fakeQuerier`) plus handler tests for
   create/get/delete happy paths, idempotent retry (same key+body → identical
   response, no second DB row), idempotency-key-reused (same key, different
   body/target), duplicate-id-fresh-key, and delete-is-idempotent (absent,
   already-deleted, and same-key replay all return 204 without re-deleting).
4. `go build ./...`, `go vet ./...`, `go test ./internal/cloudapi/...`, then
   the full `go test ./...` for regressions. Commit and push.

Note: task 5 (session minting, `internal/cloudapi/sessions.go`) landed in
parallel on this branch with its own self-contained `SessionsHandler` type
rather than extending `Server` — the two don't collide at compile time, but
task 7 (wiring `cloudapi` into `harbor-mgmt`) will need to reconcile
`Server`/`SessionsHandler`/`keys.go`'s eventual type into one thing
satisfying `cloudopenapi.ServerInterface`.
