# Design: admin-endpoint-auth-96d1d95a

## Architecture Decisions

### AD-1: Reuse `mgmtapi` bearer-token pattern

`Server.initialAccessTokenAuthorized` in `internal/mgmtapi/register.go:227-237`
already implements exactly the right pattern: SHA-256 the presented token,
`subtle.ConstantTimeCompare` against the stored hash. Hashing first eliminates
the length side-channel. We follow this pattern verbatim in a new
`AdminAuthMiddleware` in `internal/oidcapi/admin_auth.go`.

### AD-2: Path-prefix dispatcher, not handler modification

Like `WithRateLimits` in `internal/oidcapi/server.go:253-271`, we add
`WithAdminAuth(base http.Handler, mw func(http.Handler) http.Handler) http.Handler`
that matches the `/admin/` prefix. This wraps the spec-generated router without
editing `openapi.HandlerFromMux`, keeping the spec as the source of truth.
Prefix matching ensures future admin routes are protected by default.

### AD-3: Env var name `ADMIN_API_TOKEN`

The feature prompt specifies `ADMIN_API_TOKEN` (the expanded scope uses this
name). The plan body mentions `ADMIN_TOKEN`. We use `ADMIN_API_TOKEN` to match
the expanded scope requirement.

### AD-4: Boot guard mirrors `KEK_SECRET` guard

`buildSigningStack` already refuses to start when `DATABASE_URL` is set but
`KEK_SECRET` is absent. We add the same pattern for `ADMIN_API_TOKEN`: if
`DATABASE_URL` is set but `ADMIN_API_TOKEN` is absent (or too short), return an
error from `run()` before the server starts.

### AD-5: Minimum token length 32 bytes

Tokens shorter than 32 bytes are rejected at startup with a fatal error. This
rejects weak tokens before they can be used, not per-request.

### AD-6: `WWW-Authenticate: Bearer error="invalid_token"`

Per RFC 6750 §3 and the OpenAPI spec's documented 401, the response header
is `WWW-Authenticate: Bearer error="invalid_token"`. Response body uses the
standard `writeError` envelope.

## Files Affected

| File | Change |
|------|--------|
| `internal/oidcapi/admin_auth.go` | New: `AdminAuthConfig`, `AdminAuthMiddleware` |
| `internal/oidcapi/admin_auth_test.go` | New: comprehensive middleware tests |
| `internal/oidcapi/server.go` | Add `WithAdminAuth` dispatcher |
| `internal/oidcapi/admin_keys.go` | Comment cleanup |
| `internal/oidcapi/revoke_jwt.go` | Comment cleanup |
| `cmd/harbor-hot/main.go` | Boot guard + handler wiring + rate limits |
| `api/openapi/harbor.yaml` | Add `security:` blocks to admin operations |
| `deploy/k8s/ingress.yaml` | Block `/admin/` at ingress |
| `deploy/k8s/secret-hot.yaml` | Add `ADMIN_API_TOKEN` placeholder |
| `deploy/helm/templates/secret-hot.yaml` | Add `ADMIN_API_TOKEN` from values |
| `deploy/helm/values.yaml` | Add `hot.secrets.adminApiToken` |
| `internal/telemetry/labels.go` | Add `EndpointAdminRotate`, `EndpointAdminRevoke` |
| `docs/plans/production-readiness.md` | Mark blocker 1.5 resolved |
