# Tasks: Consent management UI (user privacy dashboard)

## Prerequisites

- [ ] **No DB migration** — pure composition over shipped user-scoped primitives
  (`consent-ledger` ✅ grants list/revoke, `user-audit-trail` decrypted read,
  the session + WebAuthn stores, `bff-session-middleware` ✅). Soft-surfaces the
  `email-relay-service` toggle. This change reserves no migration prefix and
  adds no new authorization model.
- [ ] **Gate 3** — lands after the Gate-1 guardrails
  (`regional-data-residency-routing`, `observability-metrics`) and Gate-2
  (`user-account-recovery`).

## Implementation

- [ ] `internal/bff/dashboard.go`: authenticated dashboard route(s) gated by the
  shipped session middleware; region-pinned reads.
- [ ] Connected-apps view: list the caller's consent grants (scopes, granted-at,
  last-used) from `consent-ledger`.
- [ ] Revoke-app action: call the shipped consent-revoke (cascades RP
  token/session revocation); reflect the change.
- [ ] Activity view: render the caller's **own decrypted** `user-audit-trail`
  events; decrypt under the caller's DEK only; no operator plaintext path.
- [ ] Sessions & devices view: list + revoke active sessions / registered
  authenticators (reuse shipped stores).
- [ ] Soft per-RP email-relay toggle wired to `email-relay-service` when present;
  gracefully absent/disabled when relay isn't deployed.
- [ ] `web/` dashboard templates/assets, server-rendered via the BFF;
  contextually escape RP/user-supplied strings (XSS-safe); no PII in client
  logs/analytics; aggregate-only UI metrics.

## Tests

- [ ] A user sees only their own grants / activity / sessions.
- [ ] Revoking an app cascades the RP revocation and updates the view.
- [ ] The activity view decrypts under the caller's DEK only; another user's data
  is never exposed; no operator plaintext path via the UI.
- [ ] The relay toggle degrades gracefully when `email-relay-service` is absent.
- [ ] RP/user strings are contextually escaped (no XSS); UI metrics are
  aggregate-only.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate consent-management-ui --strict`
