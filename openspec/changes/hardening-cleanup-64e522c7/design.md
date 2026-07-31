## Technical Approach

### 1. CSRF Defence (internal/bff/csrf.go)

New `DashboardCSRF(host string) func(http.Handler) http.Handler` middleware. Applied only to the four mutating POST routes in `DashboardHandler.Routes`. Algorithm:
1. If method != POST, pass through.
2. Check `Sec-Fetch-Site`: if present and not `same-origin`/`none`, return 403.
3. If absent, check `Origin`: if present and doesn't match `host`, return 403.
4. If neither header present, pass through (legacy UA compatibility).

No synchroniser token needed — server-rendered html/template with no JS build step.

### 2. Panic Recovery (internal/httpserver/server.go)

New `WithRecovery(logger, counter) func(http.Handler) http.Handler` applied in `Run()`. Uses `defer/recover`. On catch: `slog.Error` with fixed message + stack depth (no panic value, no PII), increment `DimOutcome` counter, write 500 with static body. Both `cmd/harbor-hot` and `cmd/harbor-mgmt` benefit automatically via shared `httpserver.Run`.

### 3. Nil-deref Guards (internal/bff/dashboard.go)

Add nil guards to `GetConnectedApps`, `GetSessions`, `PostRevokeApp`, `PostRevokeSession`, `PostRevokeCredential` — return 503 when the required dep is nil, matching the existing pattern for `relay`.

### 4. Relay Domain Threading (internal/relay/address.go)

Change `FormatEmail(token, reg, relayDomain string)` — drop the hardcoded `relay.<region>.harbor.id` suffix, use `relayDomain` instead. Update the one call site in `internal/mgmtapi/relay.go:217` to pass `s.relayDomain`. Update `internal/relay/address_test.go`.

### 5. Discovery Fixes (internal/oidcapi/discovery.go)

Remove `EdDSA` from `IdTokenSigningAlgValuesSupported`. Add optional pointer fields for `RevocationEndpoint`, `IntrospectionEndpoint`, `RegistrationEndpoint` pointing to `base+"/revoke"`, `base+"/introspect"`, `base+"/register"`. Update `api/openapi/harbor.yaml` `OpenIDProviderMetadata` schema to match.

### 6. Pool Sizing (internal/clients/pool.go)

Parse `DB_MAX_CONNS` (default 10), `DB_MIN_CONNS` (default 2), `DB_MAX_CONN_LIFETIME` (default 30m) env vars. Build `pgxpool.Config` with these values before calling `pgxpool.NewWithConfig`. Document: 20 replicas × 10 max = 200; Postgres default max_connections=100, so default intentionally conservative. Log the configured values at startup.

### 7. Git Hygiene (.gitignore + git rm)

Add unanchored `harbor-hot` and `harbor-mgmt` patterns to `.gitignore`. Add `/bin/` entry. Extend `tools/lint/filesize/filesize.go` to check for committed binary files exceeding a size threshold (e.g., 1 MB). Run `git rm --cached cmd/harbor-hot/harbor-hot`.

### 8. Migration 0017 Header (db/migrations/0017_logout_uris.up.sql)

Prepend `SET lock_timeout = '3s'; SET statement_timeout = '30s';` lines matching the pattern in 0001–0016. Add comment noting 0014 gap.

### 9. XFF Trusted-hop Model (internal/oidcapi/ratelimit.go)

Change `RateLimitConfig` to add `TrustedProxyHops int` (read from `TRUSTED_PROXY_HOPS` env, default 0). Update `clientIP`: when hops=0 use RemoteAddr; when hops>0 split the header, take `len(entries) - hops` index if valid, else RemoteAddr. Document in `deploy/README.md`.
