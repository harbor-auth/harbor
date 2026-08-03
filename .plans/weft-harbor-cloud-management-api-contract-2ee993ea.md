# Define the harbor-cloud management API OpenAPI contract

1. Read the openspec change artifacts (proposal/design/tasks/spec) for
   `harbor-cloud-management-api-contract-2ee993ea` to pin down the exact
   routes, scopes, error codes, and idempotency semantics.
2. Author `api/openapi/harbor-cloud.yaml` (OpenAPI 3.1, Apache-2.0) with
   `POST /admin/v1/sessions`, `POST /admin/v1/namespaces`,
   `GET /admin/v1/namespaces/{id}`, `DELETE /admin/v1/namespaces/{id}`,
   `POST /admin/v1/keys/rotate`; a `cloudServiceAuth` bearer scheme; a
   required `Idempotency-Key` header on create/delete/mint; and a stable
   `Error` schema covering namespace_already_exists,
   idempotency_key_reused, cross_tenant_forbidden, session_expired,
   insufficient_scope, token_replayed, rate_limited.
3. Add a dedicated `oapi-codegen-cloud.yaml` config (separate Go package
   from `harbor.gen.go` to avoid schema-name collisions) and wire it into
   `make generate`.
4. Run `make generate`, keep only the new `internal/gen/openapi/cloud/`
   output (revert unrelated pre-existing tool-version drift in
   `internal/gen/db/**` and `harbor.gen.go` from local sqlc/oapi-codegen
   version skew).
5. Verify `go build ./...` and `go vet ./...` stay green, commit, rebase,
   and push.
