## Prerequisites

- `docs/plans/admin-endpoint-auth.md` pattern (constant-time Bearer compare,
  fail-closed) is the template for the new service-auth verifier.
- Redis is already a hard dependency of harbor-mgmt (BFF/enrollment
  sessions) — no new infra dependency for the replay guard.
- `mgmt.cloudIntegration` Helm/NetworkPolicy scaffold already exists
  (`deploy/helm/values.yaml`, `deploy/helm/templates/networkpolicy-mgmt.yaml`)
  and only needs routes behind it, not new network primitives.

## 1. Contract — `api/openapi/harbor-cloud.yaml`

- [ ] 1.1 New OpenAPI 3.1 file (Apache-2.0 header comment) defining
      `POST /admin/v1/sessions`, `POST /admin/v1/namespaces`,
      `GET /admin/v1/namespaces/{id}`, `DELETE /admin/v1/namespaces/{id}`,
      `POST /admin/v1/keys/rotate`, a `cloudServiceAuth` bearer security
      scheme, `Idempotency-Key` as a required header parameter on
      create/delete/mint, and stable machine-readable error schemas.
- [ ] 1.2 `make codegen` — regenerate any Go stubs / docs from the new spec;
      commit generated output alongside the spec (no hand-edits to generated
      files).

## 2. Migration + domain model — `db/migrations/0019_cloud_namespaces.{up,down}.sql`

- [ ] 2.1 `cloud_namespaces(id text primary key, status text, created_at,
      updated_at, deleted_at)`.
- [ ] 2.2 `cloud_operations(idempotency_key text, operation text,
      request_hash bytea, response_body jsonb, created_at, primary key
      (idempotency_key, operation))`.
- [ ] 2.3 `cloud_sessions(session_id text primary key, namespace_id text
      references cloud_namespaces(id), token_hash bytea, expires_at,
      consumed_at, created_at)`.
- [ ] 2.4 sqlc queries + generated code for all three tables.

## 3. Service auth — `internal/cloudapi/serviceauth.go`

- [ ] 3.1 `ServiceClaims` + `ServiceAuthVerifier.Verify` — parse/validate
      ES256/EdDSA JWT, check `aud`, `exp`, required `scope`.
- [ ] 3.2 Redis-backed `jti` replay guard (`SETNX` + TTL = token `exp`).
- [ ] 3.3 Fail-closed when `CLOUD_SERVICE_AUTH_PUBLIC_KEY` unset — every
      request 401.
- [ ] 3.4 Audit event emission (`internal/telemetry`, PII-free) on every
      accept/reject.
- [ ] 3.5 Unit tests: valid, wrong-aud, missing-scope, expired, replayed,
      unconfigured-trust-anchor — all six paths.

## 4. Namespace handlers — `internal/cloudapi/namespaces.go`

- [ ] 4.1 `POST /admin/v1/namespaces`: idempotency-key ledger check → create
      → 409 on duplicate id or reused-key-different-body.
- [ ] 4.2 `GET /admin/v1/namespaces/{id}`: 404 machine-readable error on
      absent/deleted.
- [ ] 4.3 `DELETE /admin/v1/namespaces/{id}`: soft-delete, 204 always
      (including already-absent).
- [ ] 4.4 Unit tests for all three plus idempotent-retry and duplicate-id
      cases.

## 5. Session handlers — `internal/cloudapi/sessions.go`

- [ ] 5.1 `POST /admin/v1/sessions`: idempotency-key ledger check → mint
      opaque token (hash stored, plaintext returned once, mirrors
      `mgmtapi/register.go`'s credential-minting pattern) bound to
      `namespace_id`.
- [ ] 5.2 Session-bearer verification helper: namespace-binding check →
      `403 cross_tenant_forbidden` on mismatch, `410 session_expired` past
      `expires_at`.
- [ ] 5.3 Unit tests: idempotent retry, expiry, cross-tenant mismatch.

## 6. Key rotation proxy — `internal/cloudapi/keys.go` + `internal/oidcapi/admin_auth.go`

- [ ] 6.1 Extend `AdminAuthConfig`/`AdminAuthMiddleware` to accept a set of
      independently-labeled tokens (`ADMIN_API_TOKEN` → `operator`,
      `MGMT_HOT_PROXY_TOKEN` → `cloud-proxy`); log which credential matched.
- [ ] 6.2 `POST /admin/v1/keys/rotate` on mgmt: require `keys:rotate` scope,
      then call harbor-hot's unmodified `/admin/keys/rotate` with
      `MGMT_HOT_PROXY_TOKEN`.
- [ ] 6.3 Unit tests: scope enforcement, proxy call uses the correct
      credential, harbor-hot audit log distinguishes `operator` vs
      `cloud-proxy`.

## 7. Binary + network wiring

- [ ] 7.1 `cmd/harbor-mgmt/main.go`: register `internal/cloudapi` routes on
      the mux only when `cloudIntegration.enabled` (env-driven); read
      `CLOUD_SERVICE_AUTH_PUBLIC_KEY`, `MGMT_HOT_PROXY_TOKEN`,
      `HARBOR_HOT_INTERNAL_URL`.
- [ ] 7.2 `deploy/helm/values.yaml` + `deploy/helm/templates/`: wire the new
      secrets/env, keep `cloudIntegration.enabled: false` as the shipped
      default.
- [ ] 7.3 `deploy/k8s/`: mirror the same env/secret wiring for the raw
      manifests.
- [ ] 7.4 Per-route rate limits for all five `/admin/v1/*` paths
      (fail-closed if the limiter backend is unavailable).

## 8. Contract fixtures + integration/security tests

- [ ] 8.1 JSON fixtures under `internal/cloudapi/testdata/contract/` (request/
      response pairs) for every scenario in
      `openspec/changes/harbor-cloud-management-api-contract-2ee993ea/specs/harbor-cloud-management-api/spec.md`.
- [ ] 8.2 Fixture-driven contract test validating handlers against
      `api/openapi/harbor-cloud.yaml` (no harbor-cloud import).
- [ ] 8.3 Cross-process integration test (`-tags=integration`, real
      Postgres/Redis) covering: authorized, wrong-audience, missing-scope,
      expired, replayed, cross-tenant.
- [ ] 8.4 Assert harbor-hot's route table has no `/admin/v1/*` path, and that
      mgmt returns 404 for `/admin/v1/*` when `cloudIntegration.enabled=false`.

## 9. Invariants + docs

- [ ] 9.1 `invariants/registry.yaml`: add `INV-CLOUDAPI-SERVICE-AUTH` (scoped
      JWT, never the operator/initial-access token) and
      `INV-CLOUDAPI-REPLAY-RESISTANT` (jti replay guard), each tagged
      `//harbor:invariant` in the corresponding test.
- [ ] 9.2 `deploy/README.md`: new "Harbor Cloud management API" section
      documenting the private-path-only reachability and the two internal
      credentials.
- [ ] 9.3 `docs/design/architecture/` (or `docs/ARCHITECTURE.md` cross-ref):
      document the mgmt→hot key-rotation proxy hop.
- [ ] 9.4 `docs/plans/` + `docs/README.md`: add this plan's row.

## Validation

- [ ] `openspec validate harbor-cloud-management-api-contract-2ee993ea --strict`
- [ ] `make agent-check` green (gofmt · build · vet · tests · invariants
      meta-test · piifields · golangci-lint · buf lint · docs-design-refs ·
      docs-links)
