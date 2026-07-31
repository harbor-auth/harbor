# hardening-cleanup

A batch of nine focused **security-hardening and cleanup** fixes across the Harbor
codebase — individually small, collectively risk-reducing, and each independently
reviewable. Behavior-preserving except where a fix closes a security gap.

## Summary

1. **Dashboard CSRF** (`internal/bff/csrf.go`) — `DashboardCSRF` middleware checks
   `Sec-Fetch-Site` with an `Origin`-vs-host fallback; cross-site POSTs get 403.
2. **Panic recovery** (`internal/httpserver/recovery.go`) — `WithRecovery` recovers
   panics, logs ERROR with no PII, bumps `harbor_http_panics_total`, returns 500.
3. **Nil-safe dashboard** (`internal/bff/dashboard.go`) — nil-check consents,
   sessions, and credentials in `DashboardHandler`.
4. **RELAY_DOMAIN threading** (`internal/relay/address.go`) —
   `FormatEmail(token, relayDomain string)` sources the domain from `RELAY_DOMAIN`
   instead of hardcoding it.
5. **OIDC discovery fix** (`internal/oidcapi/discovery.go`) — drop unsupported
   `EdDSA`; advertise `revocation_endpoint` + `introspection_endpoint`.
6. **Explicit pool sizing** (`internal/clients/pool.go`) — `DB_MAX_CONNS` (10),
   `DB_MIN_CONNS` (2), `DB_MAX_CONN_LIFETIME` (30m) from env.
7. **Remove committed binary** — delete the build artifact and fix `.gitignore`.
8. **Migration timeouts** — `SET lock_timeout`/`statement_timeout` on migration
   0017; note the 0014 numbering gap.
9. **Trusted-proxy-hop client IP** (`internal/oidcapi/ratelimit.go`) —
   `TRUSTED_PROXY_HOPS=N` selects the Nth-from-right `X-Forwarded-For` value,
   replacing the spoofable leftmost-XFF model.

## Files Changed

- `internal/bff/csrf.go` — new CSRF middleware
- `internal/bff/dashboard.go` — nil-check dashboard deps, apply CSRF middleware
- `internal/httpserver/recovery.go` — new `WithRecovery` panic middleware
- `internal/httpserver/server.go` — wire `WithRecovery` in `Run`
- `internal/relay/address.go` — `FormatEmail` accepts explicit domain parameter
- `internal/mgmtapi/relay.go` — thread `RELAY_DOMAIN` through call site
- `internal/oidcapi/discovery.go` — drop `EdDSA`, add revocation/introspection endpoints
- `internal/clients/pool.go` — explicit pool sizing from env
- `internal/oidcapi/ratelimit.go` — trusted-proxy-hop client IP model
- `.gitignore` — fix binary exclusion for nested paths
- `db/migrations/0017_logout_uris.up.sql` — add lock/statement timeouts
- `deploy/README.md` — document `TRUSTED_PROXY_HOPS` and nginx-ingress interaction
