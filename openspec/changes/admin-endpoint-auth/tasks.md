# admin-endpoint-auth — Tasks

> Plan: `docs/plans/admin-endpoint-auth.md` · Blocker 1.5 in
> `docs/plans/production-readiness.md`. Guards `POST /admin/keys/rotate` and
> `POST /admin/revoke-jwt` on harbor-hot.

## 1. Middleware — `internal/oidcapi/admin_auth.go` (new)

- [ ] `AdminAuthConfig{Token string; Logger *slog.Logger}` +
      `AdminAuthMiddleware(cfg) func(http.Handler) http.Handler`.
- [ ] Require `Authorization: Bearer <token>` (scheme match case-insensitive
      per RFC 7235).
- [ ] Constant-time verify: compare SHA-256 of presented vs SHA-256 of
      configured token via `subtle.ConstantTimeCompare` (hash-first kills the
      length side-channel; mirrors `internal/mgmtapi/register.go` pattern).
- [ ] Fail-closed: empty/unset configured token → always 401 (never
      passthrough).
- [ ] 401 body via `writeError(w, 401, "unauthorized", ...)` +
      `WWW-Authenticate: Bearer` header; never echo or log the presented
      token.
- [ ] Log WARN on rejection, INFO on success (path + outcome only — no token
      material, no PII).

## 2. Router wiring — `internal/oidcapi/server.go`

- [ ] Add `WithAdminAuth(base http.Handler, mw func(http.Handler) http.Handler) http.Handler`
      dispatching on the `/admin/` **path prefix** (all methods), analogous to
      `WithRateLimits` — future admin routes are protected by default.

## 3. Binary wiring — `cmd/harbor-hot/main.go`

- [ ] Read `ADMIN_TOKEN` from env; enforce a minimum length (≥ 32 chars) at
      startup — reject weak tokens with a fatal error.
- [ ] Wrap the handler chain: `handler = oidcapi.WithAdminAuth(handler, mw)`.
- [ ] Production guard: `ADMIN_TOKEN` unset → log error; `/admin/*` serves 401
      (fail-closed), never open.
- [ ] Add `ADMIN_TOKEN` as a Kubernetes Secret `secretKeyRef` in the
      harbor-hot Deployment (ArgoCD/Helm values); document in the main.go
      package comment.

## 4. Comment / scaffold cleanup

- [ ] `internal/oidcapi/admin_keys.go`: replace "enforced by middleware wired
      in front of this handler … assumes the caller is already authorized"
      with a pointer to the real `WithAdminAuth` enforcement point.
- [ ] `internal/oidcapi/revoke_jwt.go`: same cleanup.

## 5. Tests

- [ ] `internal/oidcapi/admin_auth_test.go`:
  - [ ] missing header → 401; rotator/revoker NOT invoked (fake call count).
  - [ ] wrong token → 401; correct token → 200 + handler invoked.
  - [ ] empty configured token → 401 for all `/admin/*` (fail-closed).
  - [ ] scheme case-insensitivity (`bearer`/`Bearer`); malformed header → 401.
  - [ ] non-admin paths (`/token`, `/jwks.json`, `/healthz`) pass through
        untouched.
  - [ ] both `/admin/keys/rotate` and `/admin/revoke-jwt` covered end-to-end
        through the wrapped `openapi.Handler`.
- [ ] Verify no timing-variable comparison (`==`, `bytes.Equal`) on the token
      anywhere in the new code.
- [ ] `go build ./... && go test ./...` green.

## 6. Docs / hygiene

- [ ] Strike blocker 1.5 in `docs/plans/production-readiness.md` in the same
      change.
- [ ] Confirm the OpenAPI spec's documented 401 on admin endpoints now matches
      reality (no spec change expected — 401 was already declared).
