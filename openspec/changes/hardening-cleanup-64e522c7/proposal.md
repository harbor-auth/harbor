---
slug: hardening-cleanup-64e522c7
plan: docs/plans/hardening-cleanup.md
---

# Proposal: Security Hardening & Cleanup

## Problem

An internal review surfaced a cluster of security and correctness gaps that are
individually small but collectively raise real risk for an OIDC provider:

- Dashboard mutations have no CSRF protection beyond `SameSite=Strict` — a
  cross-site form post can act as the logged-in user.
- An unhandled panic in any handler crashes the request with no response body,
  no metric, and no structured log.
- `DashboardHandler` dereferences consents/sessions/credentials without nil
  checks, causing 500s when those deps are absent.
- The relay hardcodes `@relay.<region>.harbor.id` instead of honoring
  `RELAY_DOMAIN`.
- OIDC discovery advertises an unsupported `EdDSA` alg and omits the
  revocation and introspection endpoints it actually serves.
- The pgxpool uses driver defaults with no explicit sizing, risking connection
  exhaustion under an HPA-scaled deployment.
- A compiled binary was committed to the repository.
- Migration 0017 acquires locks with no timeout, risking an unbounded stall.
- The rate limiter trusts the leftmost `X-Forwarded-For` value, which a client
  can spoof to evade limits.

## Proposed Solution

Land nine focused, independently-reviewable fixes:

1. `DashboardCSRF` middleware — `Sec-Fetch-Site` check with `Origin` fallback,
   403 on cross-site (`internal/bff/csrf.go`).
2. `WithRecovery` panic middleware — logs ERROR (no PII), increments
   `harbor_http_panics_total`, returns 500 (`internal/httpserver/recovery.go`).
3. Nil-check consents/sessions/credentials in `DashboardHandler`.
4. Thread `RELAY_DOMAIN` through `relay.FormatEmail(token, relayDomain string)`.
5. Fix OIDC discovery — drop `EdDSA`, add `revocation_endpoint` +
   `introspection_endpoint`.
6. Explicit pgxpool sizing from env — `DB_MAX_CONNS` (10), `DB_MIN_CONNS` (2),
   `DB_MAX_CONN_LIFETIME` (30m).
7. Remove the committed binary and fix `.gitignore`.
8. Add `SET lock_timeout`/`statement_timeout` to migration 0017; note the
   0014 gap.
9. Replace leftmost-XFF with a trusted-proxy-hop model —
   `TRUSTED_PROXY_HOPS=N`, take the Nth-from-right XFF value.

## Non-Goals

- No new features or endpoints; behavior-preserving hardening only.
- No DB schema changes beyond the timeout guards on migration 0017.
- No changes to the auth/token issuance flow.
- No rewrite of the logging or metrics stack.

## Success Criteria

- [ ] Cross-site dashboard mutations receive 403; same-site requests pass.
- [ ] A handler panic returns 500, logs ERROR with no PII, and bumps `harbor_http_panics_total`.
- [ ] Dashboard renders for users with nil consents/sessions/credentials.
- [ ] `RELAY_DOMAIN` controls the relay address suffix.
- [ ] Discovery omits `EdDSA` and lists revocation + introspection endpoints.
- [ ] Pool honors `DB_MAX_CONNS`/`DB_MIN_CONNS`/`DB_MAX_CONN_LIFETIME`.
- [ ] Rate limiter derives client IP from `TRUSTED_PROXY_HOPS`.
- [ ] `go build ./... && go vet ./... && go test ./...` and `make agent-check` green.
