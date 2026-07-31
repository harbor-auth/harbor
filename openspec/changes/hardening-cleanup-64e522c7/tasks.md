---
slug: hardening-cleanup-64e522c7
plan: docs/plans/hardening-cleanup.md
---

# Tasks: Security Hardening & Cleanup

## Prerequisites

- [x] `docs/plans/hardening-cleanup.md` plan file authored.
- [x] No cross-feature dependencies — each fix is independently reviewable.
- [x] Only migration 0017 is touched for DB timeouts; no new schema is introduced.

## Implementation

- [x] **CSRF middleware** — `internal/bff/csrf.go`: `DashboardCSRF` middleware
  checks `Sec-Fetch-Site`, falls back to `Origin` vs request host, returns 403
  on cross-site POSTs. Applied to all four mutating dashboard routes.
- [x] **Panic recovery** — `internal/httpserver/recovery.go`: `WithRecovery`
  recovers panics, logs ERROR with no PII, increments `harbor_http_panics_total`,
  returns 500. Wired in `httpserver.Run` for both binaries.
- [x] **Nil-safe dashboard** — `internal/bff/dashboard.go`: nil-check consents,
  sessions, and credentials in `DashboardHandler` before dereferencing.
- [x] **RELAY_DOMAIN threading** — `internal/relay/address.go`: change signature
  to `FormatEmail(token, relayDomain string)` and update all call sites.
- [x] **OIDC discovery fix** — `internal/oidcapi/discovery.go`: drop `EdDSA`,
  add `revocation_endpoint` and `introspection_endpoint`.
- [x] **Explicit pool sizing** — `internal/clients/pool.go`: read `DB_MAX_CONNS`
  (default 10), `DB_MIN_CONNS` (default 2), `DB_MAX_CONN_LIFETIME` (default 30m)
  from env and apply to the pgxpool config.
- [x] **Remove committed binary** — delete the committed build artifact and
  update `.gitignore` to exclude nested binaries.
- [x] **Migration timeouts** — add `SET lock_timeout`/`SET statement_timeout` to
  migration 0017; document the 0014 numbering gap.
- [x] **Trusted-proxy-hop client IP** — `internal/oidcapi/ratelimit.go`: replace
  leftmost-XFF with `TRUSTED_PROXY_HOPS=N` model, taking Nth-from-right value.
  Document the nginx-ingress interaction in `deploy/README.md`.

## Tests

- [x] CSRF: cross-site POST → 403; same-origin POST → 200; `Sec-Fetch-Site: cross-site` → 403; Origin fallback mismatch → 403; absent headers → pass.
- [x] Recovery: panicking handler → 500, ERROR log with no PII, `harbor_http_panics_total` incremented; `http.ErrAbortHandler` → re-panicked.
- [x] Dashboard: user with nil consents/sessions/credentials renders without panic or 500.
- [x] Relay: `FormatEmail(token, "relay.example.com")` → address suffixed with the configured domain.
- [x] Discovery: document omits `EdDSA` and includes both `revocation_endpoint` and `introspection_endpoint`.
- [x] Pool: env overrides honored; documented defaults applied when unset.
- [x] Rate limiter: `TRUSTED_PROXY_HOPS=1` → Nth-from-right XFF; `TRUSTED_PROXY_HOPS=0` → `RemoteAddr`; forged leftmost entry cannot change the bucket.
- [x] Migration 0017: SQL contains `SET lock_timeout` and `SET statement_timeout`.

## Validation

- [x] `go build ./... && go vet ./...` — exit 0.
- [x] `go test ./...` — all packages pass.
- [x] `make agent-check` — green.
- [x] `openspec validate hardening-cleanup-64e522c7 --strict` — clean.
