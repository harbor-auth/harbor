---
title: Client & Grant Persistence (RP registry + consent store)
status: implemented
design_refs: [§10, §3.2, §11.3]
code:  [internal/clients/, internal/oidc/, db/queries/]
spec:  []
tests: [internal/clients/]
depends_on: [oidc-authorization-code, ppid-identity]
plan: client-grant-persistence
last_reconciled: 2026-07-20
---

# Client & Grant Persistence (RP registry + consent store)

## Summary

Harbor persists **relying-party (RP) client registrations** and **user↔RP
consent grants** in Postgres, replacing the in-memory `demo-client` registry
that evaporated on restart. Two sqlc-backed stores sit behind the existing
`oidc.ClientRegistry` and a new `oidc.GrantStore` seam: `clients.DBClientRegistry`
resolves clients from the `relying_parties` table (docs/DESIGN.md §10), and
`clients.DBGrantStore` records/queries consent in the `grants` table — the
rows that carry the pairwise `sub` an RP sees (§3.2) and enable the §11.3
"remove a connected app" flow. `internal/oidc` stays free of DB types: the
domain `oidc.Grant` uses only stdlib types and `internal/clients` does the
row↔domain mapping.

## Behavior (as-built)

**RP registry (`clients.DBClientRegistry`)** — implements `oidc.ClientRegistry`
(`Lookup(ctx, clientID) (Client, bool)`) over the `GetRelyingParty` sqlc query.
It reads a registration on every `Lookup` (a TTL cache can be added later
without changing the interface). The critical field is `sector_id`, which groups
redirect URIs for PPID derivation (§3.2). Swallowed DB errors are logged via an
`atomic.Pointer[slog.Logger]` so `WithLogger` is race-free against concurrent
lookups. `redirect_uris` matching stays **exact** (§7.4) — no prefix/substring
leniency.

**Grant store (`clients.DBGrantStore`)** — implements `oidc.GrantStore`:
`FindGrant(userID, clientID) (Grant, bool, error)`, `CreateGrant`,
`RevokeGrant`, `ListGrantsByUser`, mapped onto the `grants.sql` queries.
`FindGrant` mirrors the `(T, bool, error)` convention of `ClientRegistry.Lookup`
(returns `false` when no active grant exists). First consent creates the grant,
recording the `pairwise_sub` the RP will see; the `UNIQUE (user_id, client_id)`
index means revoke-then-reconsent issues a **new** grant row while the old
revoked row stays for audit but is excluded from the active lookup.

**Domain types (`oidc.grants`)** — `oidc.Grant` (ID, Region, UserID, ClientID,
PairwiseSub, Scopes, CreatedAt, RevokedAt) and `oidc.NewGrant` (the store mints
the ID + CreatedAt; the caller supplies the region so the row satisfies the
user-owned-row contract, §10). An in-memory `GrantStore` stub is available for
unit tests that don't need a live DB.

## Interfaces / Endpoints

- No new HTTP endpoints — the `/authorize` flow is untouched; it now resolves
  clients from Postgres instead of memory.
- Exported Go surface:
  - `clients.NewDBClientRegistry(q) *DBClientRegistry` (implements `oidc.ClientRegistry`).
  - `clients.NewDBGrantStore(q) *DBGrantStore` (implements `oidc.GrantStore`).
  - `oidc.Grant`, `oidc.NewGrant`, `oidc.GrantStore` interface (+ in-memory stub).
- Contract / storage:
  - `db/queries/relying_parties.sql` — `GetRelyingParty`, `ListRelyingParties`, `UpsertRelyingParty`.
  - `db/queries/grants.sql` — find/create/revoke/list by user (sqlc-generated types in `internal/gen/db`).

## Code map

| Path | Role |
|---|---|
| `internal/oidc/grants.go` | Domain `Grant`/`NewGrant` + `GrantStore` interface (stdlib-only, no DB deps) + in-memory stub. |
| `internal/clients/registry.go` | `DBClientRegistry` — sqlc-backed `oidc.ClientRegistry` over `relying_parties`. |
| `internal/clients/grants.go` | `DBGrantStore` — sqlc-backed `oidc.GrantStore` over `grants`. |
| `db/queries/relying_parties.sql` | RP registry queries (Get/List/Upsert). |
| `db/queries/grants.sql` | Consent-grant queries (find/create/revoke/list). |
| `cmd/harbor-hot/main.go` | Wires the DB-backed registry + grant store into the service. |

## Security & privacy invariants

- **Active-only grant reads (§10, §11.3)** — `INV-GRANT-ACTIVE-ONLY`: `FindGrant`
  never returns a revoked grant; the `UNIQUE (user_id, client_id)` index keeps
  the revoked row for audit while excluding it from the active lookup.
- **PPID frozen at consent (§3.2)** — `INV-GRANT-PPID-BOUND`: a grant's
  `pairwise_sub` is the PPID computed at consent time and is immutable, so RP
  tokens stay stable even if PPID derivation inputs later change.
- **Exact redirect-URI matching (§7.4)** — the DB-backed registry preserves the
  exact-match contract; no prefix/substring/trailing-slash leniency.
- **User-owned rows carry region (§5, §10)** — grants are written with the
  user's home region so the row satisfies the residency contract.

## Tests

- `internal/clients/registry_test.go` — unknown client → not found; row → `oidc.Client`
  mapping incl. `sector_id`; exact redirect-URI list preserved.
- `internal/clients/grants_test.go` — grant create/find/revoke/list; active-only
  after revoke (`INV-GRANT-ACTIVE-ONLY`); PPID immutability (`INV-GRANT-PPID-BOUND`);
  region populated on writes. Both use small sqlc fakes (`fakeRPQuerier`,
  `grantQuerier`) so the pure logic tests without a live Postgres.

## Known gaps / TODOs

- **RP onboarding is seed-only** — `relying_parties` rows are written via
  migration/admin tooling (`UpsertRelyingParty`); a real self-service RP
  registration API is management-plane work (§4.1) tracked separately.
- **No registry cache yet** — `Lookup` hits the DB per call; an in-process TTL
  cache can be added behind the unchanged interface if the hot path needs it.
- Consumed by [session-ppid-seam](session-ppid-seam.md), which reads/writes
  grants to resolve the per-RP PPID at login/consent.
