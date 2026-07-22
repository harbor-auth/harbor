# Proposal: Client & grant persistence (RP registry + consent store)

## Problem

The RP client registry is in-memory with a hardcoded `demo-client` in
`cmd/harbor-hot/main.go` — it evaporates on restart and can't be managed.
Consent `grants` have real sqlc queries (`db/queries/grants.sql`) but nothing
calls them, so a user's consent is never persisted and "remove a connected app"
(§11.3) is impossible.

## Proposed Solution

- Add `db/queries/relying_parties.sql` for the §10 RP registry table and a
  sqlc-backed `ClientRegistry` satisfying the existing `oidc.ClientRegistry`
  interface — including the `sector_id` used for PPID grouping (§3.2).
- Add an `oidc.GrantStore` interface and a sqlc-backed implementation over
  `grants.sql` (find / create / revoke / list), so first consent persists a
  grant recording the `pairwise_sub` the RP sees.
- Wire both into `cmd/harbor-hot/main.go`, keeping the in-memory registry for
  hermetic tests.

## Non-Goals

- Deriving/using the PPID at login (that's `session-ppid-seam`).
- A public RP self-registration API (management-plane, separate plan).
- Any change to redirect-URI matching semantics (stays exact, §7.4).

## Success Criteria

- [ ] `/authorize` resolves clients from Postgres via sqlc.
- [ ] Consent grants persist to the `grants` table and can be listed/revoked.
- [ ] Unknown client ⇒ not found; exact redirect-URI matching preserved.
- [ ] `region` populated on every write; in-memory registry retained for tests.
- [ ] `make agent-check` clean.
