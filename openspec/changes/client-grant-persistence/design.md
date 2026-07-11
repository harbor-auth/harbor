# Design: Client & grant persistence

## Key Decisions

### Decision 1: Satisfy the existing `ClientRegistry` interface
**Chosen:** New sqlc-backed type implements the current `oidc.ClientRegistry`;
`/authorize` is untouched.
**Rationale:** The seam already exists; swapping the implementation keeps the
flow logic and its tests stable.
**Alternatives considered:** New interface shape (needless churn, rejected).

### Decision 2: `GrantStore` as a new seam, mapped onto existing queries
**Chosen:** Add `oidc.GrantStore`; back it with the already-written
`grants.sql` queries.
**Rationale:** The queries exist and are the contract (§1.3); we only need the
Go seam + a mapper. Keeps the flow package storage-agnostic.
**Alternatives considered:** Calling sqlc directly from the service (couples
flow logic to the DB, rejected).

### Decision 3: Keep the in-memory registry for tests
**Chosen:** Retain `NewInMemoryClientRegistry` behind the interface.
**Rationale:** Hermetic unit tests (F3) shouldn't need Postgres; both share the
interface.

### Decision 4: `sector_id` is registry-owned
**Chosen:** The `relying_parties.sector_id` column is the single source of the
PPID grouping key.
**Rationale:** §3.2 unlinkability depends on a stable, auditable sector mapping;
putting it on the RP row keeps it explicit and management-controlled.

### Decision 5: Add a migration only if the table is missing
**Chosen:** Check `0001`/`0002`; if `relying_parties` isn't present, add an
expand-only `0003`.
**Rationale:** Follows the expand/contract migration discipline (§1.8) and
avoids editing shipped migrations.
