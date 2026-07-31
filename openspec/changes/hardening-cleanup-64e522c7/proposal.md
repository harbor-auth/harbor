## Why

Nine independent medium/low defects — audit findings M4 and M5 — each individually manageable but together representing the gap between "security model holds" and "security model holds as long as nothing else goes wrong." None requires cross-cutting refactor; all are self-contained and safe to fix in parallel.

## What Changes

- **ADDED** `Sec-Fetch-Site`/`Origin` CSRF check middleware applied to the four mutating dashboard POSTs; `SameSite=Strict` remains but is no longer the sole layer
- **ADDED** Panic-recovery middleware in `httpserver.Run`; recovers, logs (no PII, no panic value), increments a telemetry counter, returns generic 500
- **CHANGED** `relay.FormatEmail` accepts a `relayDomain` argument instead of hardcoding `relay.<region>.harbor.id`; all call sites updated
- **CHANGED** Discovery document: removes `EdDSA` from `id_token_signing_alg_values_supported`; adds `revocation_endpoint`, `introspection_endpoint`, `registration_endpoint`
- **CHANGED** `clients.ConnectDB` reads `TRUSTED_PROXY_HOPS` and uses Nth-from-right XFF entry (default 0 = `RemoteAddr`) instead of leftmost
- **CHANGED** `clients.ConnectDB` reads `DB_MAX_CONNS`/`DB_MIN_CONNS`/`DB_MAX_CONN_LIFETIME` for explicit pool sizing
- **CHANGED** `.gitignore` fixed to match nested binary paths; `cmd/harbor-hot/harbor-hot` removed from git tracking
- **CHANGED** `db/migrations/0017_logout_uris.up.sql` gets `SET lock_timeout`/`statement_timeout` header and `0014` gap comment
- **CHANGED** Nil-check `consents`/`sessions`/`credentials` in `DashboardHandler` to prevent nil-deref panic

## Capabilities

**New Capabilities:**
- `csrf-defense` — dashboard mutating POSTs require a same-site origin signal in addition to the session cookie
- `panic-recovery` — any panicking HTTP handler produces a logged, metered, PII-free 500 instead of a silent dropped connection
- `xff-rate-limit` — rate-limit IP extraction uses a trusted-proxy-count model, preventing leftmost-XFF forgery

**Modified Capabilities:**
- `relay-address` — FormatEmail uses the configured relay domain, not a hardcoded one
- `oidc-discovery` — discovery document accurately reflects supported algorithms and available endpoints

## Impact

- `internal/bff/csrf.go` (new), `internal/bff/dashboard.go`, `internal/httpserver/server.go`
- `internal/relay/address.go`, `internal/mgmtapi/relay.go`
- `internal/oidcapi/discovery.go`, `api/openapi/harbor.yaml`
- `internal/oidcapi/ratelimit.go`, `internal/clients/pool.go`
- `.gitignore`, `db/migrations/0017_logout_uris.up.sql`, `deploy/README.md`
