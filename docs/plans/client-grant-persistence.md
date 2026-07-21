---
title: Client & grant persistence (RP registry + consent store)
status: promoted
design_refs: [§10, §3.2]
targets: [internal/oidc/, internal/clients/, db/queries/]
promoted_to: docs/features/client-grant-persistence.md
openspec: changes/client-grant-persistence
created: 2026-07-10
---

# Client & grant persistence (plan)

> **Dependency order:** *No prerequisites* (the `grants` table and its sqlc
> queries already exist; a `relying_parties` table + queries are added here).
> `session-ppid-seam` depends on this (it records the grant at first consent).

## Problem

The RP client registry is an **in-memory** `NewInMemoryClientRegistry()` with a
hardcoded `demo-client` in `cmd/harbor-hot/main.go` — it evaporates on restart
and can't be managed. Consent `grants` have real sqlc queries
(`db/queries/grants.sql`) but **nothing calls them**: a user's consent is never
persisted, so "remove a connected app" (§11.3) and the user-owned grant list are
impossible. Both the client lookup and the grant record must become DB-backed.

## Proposed approach

1. **`relying_parties` registry (sqlc-backed)** — add `db/queries/relying_parties.sql`
   for the table already sketched in §10 (`client_id`, `name`, `sector_id`,
   `redirect_uris`, `token_format`, `scopes_allowed`). Provide a
   `ClientRegistry` implementation over sqlc that satisfies the existing
   `oidc.ClientRegistry` interface (`Lookup(ctx, clientID) (Client, bool)`), so
   the `/authorize` flow is untouched. `sector_id` is the critical field — it
   groups redirect URIs for PPID derivation (§3.2).
2. **`GrantStore` interface + sqlc impl** — a new `oidc.GrantStore` seam:
   `FindGrant(ctx, userID, clientID)`, `CreateGrant(...)`, `RevokeGrant(...)`,
   `ListGrantsByUser(...)` mapped onto the existing `grants.sql` queries. First
   consent creates the grant (recording the `pairwise_sub` the RP will see);
   subsequent logins with the same scopes skip the consent screen.

This plan **persists** clients and grants; deriving the PPID and wiring it into
login/consent is `session-ppid-seam`'s job — this change just makes the storage
real so that seam has somewhere to read/write.

## DESIGN alignment

Realizes the `relying_parties` and `grants` tables in §10, and the §3.2 use of
`sector_id` as the PPID grouping key. Enables §11.3 (add/remove connected app).
Does **not** change `DESIGN.md`.

## Target code paths

- `db/queries/relying_parties.sql` — RP registry queries (regen `internal/gen/db`)
- `internal/clients/registry.go` — sqlc-backed `ClientRegistry`
- `internal/oidc/grants.go` — `GrantStore` interface
- `internal/clients/grants.go` — sqlc-backed `GrantStore`
- `cmd/harbor-hot/main.go` — wire DB-backed registry (replace in-memory)
- `internal/clients/*_test.go`

## Implementation checklist

- [ ] `db/queries/relying_parties.sql` (Get/List/Upsert); regenerate sqlc types.
- [ ] Add a `relying_parties` migration if the table isn't in `0001`/`0002` (check first; add `0003` expand-only if needed).
- [ ] sqlc-backed `ClientRegistry` satisfying `oidc.ClientRegistry`; maps row → `oidc.Client` (incl. `sector_id`).
- [ ] `oidc.GrantStore` interface + sqlc impl over `grants.sql`.
- [ ] Wire DB-backed registry into `cmd/harbor-hot/main.go`; keep the in-memory one for tests.
- [ ] Tests: unknown client → not found; exact redirect-URI match preserved; grant create/find/revoke; region column populated on writes.
- [ ] Author & verify paired OpenSpec change: `openspec validate client-grant-persistence --strict`
- [ ] Reconcile & promote: `@plan promote client-grant-persistence`

## Risks & open questions

- **RP onboarding** (who writes `relying_parties` rows) is management-plane work (§4.1 cold path) — v1 can seed via migration/admin tool; a real registration API is a separate plan.
- The in-memory registry must remain for hermetic unit tests — keep both behind the interface.
- `redirect_uris text[]` matching must stay **exact** (§7.4) — no prefix/substring matching when moving to DB.

## Definition of done

`go build/vet/test ./...` green; `/authorize` resolves clients from Postgres via
sqlc; consent grants persist to the `grants` table and can be listed/revoked;
exact redirect-URI matching preserved; `make agent-check` clean. Ready to
`@plan promote`.
