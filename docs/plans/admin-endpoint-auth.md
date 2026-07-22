# admin-endpoint-auth — Authenticate the /admin/* surface on harbor-hot

> **Priority:** P0 (Wave 6, production-readiness audit blocker 1.5)
> **Effort:** 2–4 h · **Root feature** (no dependencies)

## Problem

`POST /admin/keys/rotate` (`internal/oidcapi/admin_keys.go`) and
`POST /admin/revoke-jwt` (`internal/oidcapi/revoke_jwt.go`) sit on the
internet-facing `harbor-hot` binary with **zero authentication**. The handler
comment claims:

> "Admin authentication is enforced by middleware wired in front of this
> handler … this handler assumes the caller is already authorized."

…but no such middleware exists anywhere in the router chain
(`openapi.Handler(srv)` → `oidcapi.WithRateLimits` → serve). Any
unauthenticated caller can:

- `POST /admin/keys/rotate?emergency=true` — zero-grace key rotation,
  invalidating **every issued token** (a one-request DoS of the whole IdP);
- `POST /admin/revoke-jwt` — revoke arbitrary tokens.

## Fix

### 1. New middleware: `internal/oidcapi/admin_auth.go`

```go
// AdminAuthMiddleware guards /admin/* with a static bearer token.
func AdminAuthMiddleware(cfg AdminAuthConfig) func(http.Handler) http.Handler
```

- Config: `Token string` (from env `ADMIN_TOKEN`), `Logger *slog.Logger`.
- Check `Authorization: Bearer <token>` on every request.
- **Constant-time comparison**: hash both sides with SHA-256 first, then
  `subtle.ConstantTimeCompare(hash(presented), hash(configured))` — hashing
  first also removes the length side-channel. Follow the existing pattern in
  `internal/mgmtapi/register.go` (`validInitialAccessToken`).
- On failure: `401` with the generic error envelope (`writeError(w, 401,
  "unauthorized", "admin authentication required")`), plus
  `WWW-Authenticate: Bearer` per the OpenAPI contract's documented 401. Never
  echo the presented token; never log it.
- **Fail-closed when unconfigured**: if `ADMIN_TOKEN` is empty, the middleware
  returns `401` (or preferably harbor-hot refuses to expose `/admin/*` at all)
  — an unset env var must never mean "open".
- Minimum token length guard at construction (e.g. ≥ 32 bytes) — reject weak
  tokens at startup, not per-request.
- Emit an audit/log line at INFO for every successful admin call and WARN for
  every rejected one (path + outcome only; no token material, no PII).

### 2. Router wiring

Add a path-prefix dispatcher analogous to `WithRateLimits` in
`internal/oidcapi/server.go`:

```go
// WithAdminAuth wraps base so any request whose path starts with "/admin/"
// passes through the admin auth middleware first.
func WithAdminAuth(base http.Handler, mw func(http.Handler) http.Handler) http.Handler
```

Prefix match on `/admin/` (covers `/admin/keys/rotate`, `/admin/revoke-jwt`,
and any future admin route **by default** — a newly added admin endpoint must
not be born unauthenticated).

### 3. `cmd/harbor-hot/main.go`

```go
handler := oidcapi.WithAdminAuth(handler, oidcapi.AdminAuthMiddleware(...))
```

Read `ADMIN_TOKEN` from env (delivered via Kubernetes Secret; add it to the
Helm/ArgoCD values and deployment manifest as a secretKeyRef). If unset in a
production configuration, log an error and either exit or serve 401 on all
`/admin/*` — never pass through.

### 4. Comment cleanup

Update the stale comments in `admin_keys.go` / `revoke_jwt.go` to reference the
now-real middleware (`WithAdminAuth` in server.go) instead of a hypothetical
one. No "assumes the caller is authorized" language without a compile-visible
enforcement point.

## Non-goals / future

- mTLS client certs or OIDC-based operator SSO for admin — better long-term,
  out of scope for this P0. The middleware seam (`AdminAuthConfig`) is where a
  cert/JWT verifier plugs in later.
- Auth for `internal/mgmtapi` admin surfaces — separate binary, separate work.

## Tests (`internal/oidcapi/admin_auth_test.go` + updates)

- No `Authorization` header → 401, rotation NOT invoked (assert via fake
  rotator call count).
- Wrong token → 401; correct token → 200 and rotator invoked.
- `Bearer` scheme case-insensitivity; token with trailing whitespace rejected.
- Empty configured token → all `/admin/*` requests 401 (fail-closed).
- Non-admin paths (`/token`, `/healthz`, `/jwks.json`) unaffected by the
  wrapper.
- Both `/admin/keys/rotate` and `/admin/revoke-jwt` covered.
- Update existing `revoke_jwt_test.go` / admin_keys tests to go through the
  wrapped handler where they exercise routing.

## No scaffold remains

The "auth is someone else's job" comments are gone; every `/admin/*` route is
provably behind `WithAdminAuth` in both the router wiring and `main.go`. Update
`docs/plans/production-readiness.md` row 1.5 → Resolved in the same change.
