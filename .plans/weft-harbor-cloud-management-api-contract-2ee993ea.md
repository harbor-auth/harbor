# Implement idempotent, namespace-scoped session minting handlers

Task 5 of the harbor-cloud-management-api-contract feature.

1. Read `api/openapi/harbor-cloud.yaml`'s `SessionMintRequest`/`SessionMintResponse`
   schemas and `POST /admin/v1/sessions` operation, `design.md` §4, and
   `spec.md`'s "Namespace-scoped session minting with idempotency" requirement
   to pin down exact behavior: `Idempotency-Key`-keyed ledger replay, session
   bound strictly to `namespace_id`, 403 `cross_tenant_forbidden` /
   410 `session_expired` for subsequent bearer checks.
2. Read `internal/cloudapi/store.go` (already implemented: `Store.CreateSession`,
   `GetSession`, `CreateOperation`, `GetOperation`, `GetNamespace`) and
   `internal/mgmtapi/register.go` (the credential-minting pattern to mirror:
   mint random opaque credential, hash before persisting, return plaintext
   exactly once).
3. Add `internal/cloudapi/sessions.go`:
   - `SessionsHandler` wrapping `*Store` (+ an injectable clock for tests),
     since no shared `cloudapi.Server` type exists yet (namespace/key-rotation
     handler tasks are still pending) — self-contained, no dependency on
     files other tasks haven't written yet.
   - `PostSessions`: requires `Idempotency-Key`, decodes+validates the body,
     hashes the NORMALIZED (re-marshaled) body for ledger comparison, checks
     `cloud_operations` before minting (replay same hash -> cached response
     verbatim incl. plaintext token; different hash -> 409
     `idempotency_key_reused`), 404 `namespace_not_found` on an absent/deleted
     target namespace, mints `session_id` + opaque `secret`
     (`token = session_id + "." + secret`, only `sha256(secret)` persisted),
     clamps `ttl_seconds` to [60s, 3600s] per the spec (never rejects).
   - `VerifySessionBearer(ctx, bearer, targetNamespaceID)`: splits the
     `id.secret` token, looks up the session, constant-time-compares the
     secret hash, then checks expiry (`ErrSessionExpired`, >= expires_at) and
     namespace match (`ErrCrossTenantForbidden`) — for future namespace-scoped
     operation handlers to call.
4. Add `internal/cloudapi/sessions_test.go`: a stateful in-memory `querier` fake
   (store_test.go's fake is per-call-closure only, doesn't hold state across
   calls, so it can't exercise a retried mint) covering idempotent retry
   (same session/token returned, no second `CreateSession` call), reused key
   with a different body (409), missing namespace (404), TTL clamping, and
   `VerifySessionBearer`'s expiry / cross-tenant-mismatch / invalid-token paths.
5. `gofmt -l`, `go build ./...`, `go vet ./...`,
   `go test ./internal/cloudapi/...`, then `go test ./...` for regressions.
   Commit and push.
