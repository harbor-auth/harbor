## Prerequisites

- Go toolchain available (`go build ./...` passes on main)
- `openspec validate hardening-cleanup-64e522c7 --strict` must pass before PR

## Implementation

### Task 1 — CSRF middleware
- Create `internal/bff/csrf.go`: `DashboardCSRF(host string) func(http.Handler) http.Handler`
- Apply to four mutating POST routes in `internal/bff/dashboard.go:Routes`
- Files: `internal/bff/csrf.go`, `internal/bff/dashboard.go`

### Task 2 — Panic-recovery middleware
- Add `WithRecovery` to `internal/httpserver/server.go`, wrap handler in `Run()`
- Files: `internal/httpserver/server.go`

### Task 3 — Nil-deref guards in DashboardHandler
- Nil-check `consents`, `sessions`, `credentials` in each handler method; return 503
- Files: `internal/bff/dashboard.go`

### Task 4 — Relay domain threading
- Change `relay.FormatEmail(token, reg, relayDomain string)` signature
- Update call site in `internal/mgmtapi/relay.go:217`
- Files: `internal/relay/address.go`, `internal/mgmtapi/relay.go`

### Task 5 — Discovery document fixes
- Remove `EdDSA` from alg values; add three missing endpoints
- Update `api/openapi/harbor.yaml` OpenIDProviderMetadata schema
- Files: `internal/oidcapi/discovery.go`, `api/openapi/harbor.yaml`

### Task 6 — Pool sizing from env
- Parse `DB_MAX_CONNS`, `DB_MIN_CONNS`, `DB_MAX_CONN_LIFETIME` in `clients.ConnectDB`
- Files: `internal/clients/pool.go`

### Task 7 — Remove committed binary + fix .gitignore
- `git rm --cached cmd/harbor-hot/harbor-hot`
- Fix `.gitignore` with unanchored binary patterns
- Add binary-size check to `tools/lint/filesize/filesize.go`
- Files: `.gitignore`, `tools/lint/filesize/filesize.go`

### Task 8 — Migration 0017 header
- Prepend timeout header to `db/migrations/0017_logout_uris.up.sql`
- Add 0014 gap comment
- Files: `db/migrations/0017_logout_uris.up.sql`

### Task 9 — XFF trusted-proxy-hop model
- Add `TrustedProxyHops int` to `RateLimitConfig`; update `clientIP` logic
- Read `TRUSTED_PROXY_HOPS` env in `cmd/harbor-hot/main.go` and `cmd/harbor-mgmt/main.go`
- Document in `deploy/README.md`
- Files: `internal/oidcapi/ratelimit.go`, `cmd/harbor-hot/main.go`, `cmd/harbor-mgmt/main.go`, `deploy/README.md`

## Tests

### Task 10 — CSRF tests
- Test each mutating POST with `Sec-Fetch-Site: cross-site` => 403
- Test `Sec-Fetch-Site: same-origin` => allowed
- Test cross-origin `Origin` header => 403
- Files: `internal/bff/csrf_test.go`

### Task 11 — Panic recovery tests
- Panicking handler => 500 + metric increment + log with no panic value
- Files: `internal/httpserver/server_test.go`

### Task 12 — Relay domain tests
- `relay.FormatEmail` with custom domain matches expected format
- API response relay_email matches configured RELAY_DOMAIN
- Files: `internal/relay/address_test.go`, `internal/mgmtapi/relay_test.go`

### Task 13 — Discovery tests
- Assert `EdDSA` not in alg values
- Assert `revocation_endpoint`, `introspection_endpoint`, `registration_endpoint` present
- Files: `internal/oidcapi/discovery_test.go`

### Task 14 — XFF rate-limit tests
- Forged leftmost XFF with N=1 hops uses rightmost entry
- N=0 always uses RemoteAddr
- Files: `internal/oidcapi/ratelimit_test.go`

## Validation

- `go build ./...`
- `go vet ./...`
- `go test ./internal/bff/... ./internal/httpserver/... ./internal/relay/... ./internal/oidcapi/... ./internal/clients/...`
- `make agent-check`
- `make generate-check`
- `openspec validate hardening-cleanup-64e522c7 --strict`
