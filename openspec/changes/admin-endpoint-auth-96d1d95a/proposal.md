# Proposal: admin-endpoint-auth-96d1d95a

## Problem

`POST /admin/keys/rotate` and `POST /admin/revoke-jwt` on harbor-hot have zero
authentication. The handler comment in `internal/oidcapi/admin_keys.go:26-28`
claims "Admin authentication is enforced by middleware wired in front of this
handler" — but the actual chain is only `openapi.HandlerFromMux` → `WithRateLimits`.
Any internet-reachable caller can trigger emergency key rotation (invalidating
every outstanding token — a one-request total outage) or bulk-revoke arbitrary JTIs.

Audit finding **C2** (docs/plans/audit-2026-07-30-wiring-and-auth.md).

## Solution

Defence in depth across three layers:

1. **Middleware** (`internal/oidcapi/admin_auth.go`): `AdminAuthMiddleware` checks
   `Authorization: Bearer <token>` via SHA-256 constant-time comparison (mirrors
   `mgmtapi.initialAccessTokenAuthorized`). Returns 401 + `WWW-Authenticate: Bearer`
   on failure. Fail-closed: empty token → always 401.

2. **OpenAPI contract** (`api/openapi/harbor.yaml`): Add `security: [{bearerAuth: []}]`
   to both admin operations (documentation only — oapi-codegen does not enforce it).

3. **Network** (`deploy/k8s/ingress.yaml`, `deploy/helm/templates/ingress.yaml`):
   Block `/admin/` at the public ingress layer.

**Fail-closed boot guard**: `ADMIN_API_TOKEN` unset + `DATABASE_URL` set → refuse
to start (mirrors `KEK_SECRET` guard in `buildSigningStack`).

**Rate limiting**: Add `/admin/keys/rotate` and `/admin/revoke-jwt` to
`hotPathLimits` with tight budgets.

## Acceptance Criteria

- No header → 401; wrong token → 401; correct token → handler runs
- Boot guard: `ADMIN_API_TOKEN` unset + `DATABASE_URL` set → startup error
- `/authorize`, `/token`, `/jwks.json`, `/healthz` unaffected
- `go build ./...`, `go vet ./...`, `go test ./...` green
- `make generate-check` green
