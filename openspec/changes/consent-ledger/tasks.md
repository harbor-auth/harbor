# Tasks: Consent ledger (per-user / per-RP / per-scope consent grants)

## Prerequisites

- [ ] A **root** — no hard prerequisites. Reuses the shipped client registry
  (`client-grant-persistence`) and PPID/session seams; adds an independent,
  cold-path table and does not touch the hot-path router. `user-audit-trail` is
  **soft-gated** on this change's event taxonomy but this change stands alone.
- [ ] **Migration prefix `0011` is reserved** for this change
  (`db/migrations/0011_consent_grants.up.sql` / `.down.sql`). Do not reuse
  `0011` in any parallel in-flight change (the historical migration-collision
  failure mode).

## Implementation

- [ ] Migration `0011_consent_grants` (up/down): `consent_grants(user_id,
  client_id, scopes, granted_at, updated_at, revoked_at)`, unique
  `(user_id, client_id)`, FKs to users + clients.
- [ ] `db/queries/consent_grants.sql` + `make codegen` (sqlc): upsert-grant,
  get-by-user-client, list-by-user, revoke.
- [ ] `internal/clients/consent.go`: `ConsentStore` (get / upsert / list /
  revoke) over the generated queries; compile-time interface assertion.
- [ ] Scope-set canonicalisation (sorted / deduped) so superset & escalation
  checks are exact.
- [ ] `/authorize` enforcement (`internal/oidc/`): skip the prompt when a valid
  grant covers requested scopes; prompt + upsert on no-grant or scope
  escalation (requested ⊄ granted); treat `revoked_at` as no grant; honour
  `prompt=consent` (force) and `prompt=none` (error if consent required).
- [ ] `internal/mgmtapi/` user endpoints: list my consent grants; revoke a grant
  (`revoked_at`) and cascade a token/session revocation for that RP via the
  shipped revocation stack.
- [ ] Emit structured consent events (`consent.granted`,
  `consent.scope_escalated`, `consent.revoked`) via a seam `user-audit-trail`
  can consume; define the event schema here.

## Tests

- [ ] First authorize prompts + persists the grant.
- [ ] Repeat authorize with a subset of scopes skips the prompt.
- [ ] Scope escalation re-prompts + widens the grant.
- [ ] `prompt=consent` always re-prompts; `prompt=none` errors when consent required.
- [ ] Revoked grant re-prompts.
- [ ] Revoke endpoint sets `revoked_at` + cascades the RP token revocation.
- [ ] Security/privacy: no cross-user or cross-client grant leakage (a user only
  sees/revokes their own grants; a grant only satisfies its own `client_id`);
  no PII beyond FKs + scope strings in the row.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate consent-ledger --strict`
