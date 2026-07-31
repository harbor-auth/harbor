# Proposal: Admin Endpoint Authentication (harbor-hot)

## Problem

`POST /admin/keys/rotate` and `POST /admin/revoke-jwt` on harbor-hot have
**zero authentication**. Handler comments claim middleware is wired — but no
such middleware exists anywhere in the router chain. Any unauthenticated caller
can trigger a total-outage key rotation or revoke arbitrary tokens.

Audit finding C2 (2026-07-30) confirmed this is entirely unfixed and expanded
scope to cover three additional gaps:

1. The OpenAPI contract has no `security:` block on either admin operation.
2. Admin paths are absent from `hotPathLimits` — even with auth a leaked token
   allows unbounded rotation.
3. `deploy/k8s/ingress.yaml` routes `/` prefix to harbor-hot, making `/admin/*`
   internet-reachable with no network-layer containment.

## Proposed Solution

Defence in depth across three layers:

1. **Middleware**: `AdminAuthMiddleware` in `internal/oidcapi/admin_auth.go` —
   Bearer token auth with constant-time SHA-256 comparison (mirrors the existing
   `initialAccessTokenAuthorized` pattern in `internal/mgmtapi/register.go`).
   Wired via `WithAdminAuth` path-prefix dispatcher in `server.go`.
2. **Contract**: `security: [{bearerAuth: []}]` added to both admin operations
   in `api/openapi/harbor.yaml` so the spec documents the requirement.
3. **Network**: ingress rule denying `/admin/` on the public host.

**Fail closed**: `ADMIN_API_TOKEN` unset + `DATABASE_URL` set → refuse to boot
(mirrors `KEK_SECRET` guard). Admin rate limits added to `hotPathLimits`.

## Non-Goals

- mTLS or OIDC-based operator SSO for admin endpoints.
- Auth for `internal/mgmtapi` surfaces (separate binary).
- Client-secret auth for `/introspect` or `/revoke` (separate feature).
