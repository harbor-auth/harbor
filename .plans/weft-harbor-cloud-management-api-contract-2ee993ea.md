# Implement scoped service-JWT verifier with replay resistance

Task 3 of the harbor-cloud-management-api-contract feature.

1. Read `openspec/changes/harbor-cloud-management-api-contract-2ee993ea/design.md`
   §2 and `api/openapi/harbor-cloud.yaml`'s `cloudServiceAuth` scheme to pin down
   the exact claim/error semantics, and the existing verifier/admin-auth
   patterns (`internal/oidc/jwt_verifier.go`, `internal/oidcapi/admin_auth.go`)
   to match project conventions (hand-rolled compact-JWT parsing, no new JWT
   dependency, constant-time comparisons via SHA-256 + `subtle.ConstantTimeCompare`).
2. Add `internal/cloudapi/serviceauth.go`:
   - `ServiceClaims` (Audience, Subject, Scopes, ExpiresAt, JTI) and
     `ServiceAuthVerifier.Verify(ctx, bearer) (ServiceClaims, error)`.
   - Support ES256 and EdDSA, verified against a single configured trust
     anchor public key (PEM, from `CLOUD_SERVICE_AUTH_PUBLIC_KEY` — parsed by
     the constructor here; wiring reads the env var in a later task).
   - Fail closed when the trust anchor or the replay guard aren't configured.
   - `ReplayGuard` interface + `RedisReplayGuard` (SETNX, TTL = token exp).
   - PII-free audit event via `internal/telemetry` on every accept/reject
     (adds an allow-listed `caller` field for the machine service-identity
     subject; reuses `path_template`/`result`/`error_code`).
   - Never accept `ADMIN_API_TOKEN` or the RFC 7591 initial-access token —
     this verifier only ever parses/verifies the bearer JWT it's handed.
3. Add `internal/cloudapi/serviceauth_test.go` covering: valid, wrong-audience,
   missing-scope, expired, replayed, unconfigured-trust-anchor (plus malformed
   token / wrong-algorithm / unconfigured-replay-guard as bonus coverage).
4. `go build ./...`, `go vet ./...`, `go test ./internal/cloudapi/... ./internal/telemetry/...`,
   then the full `go test ./...` for regressions. Commit and push.
