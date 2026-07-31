---
title: Unify the two consent tables so revoking consent actually revokes consent
status: draft
design_refs: [§11.3, §3.2, §10]
targets: [db/migrations/, db/queries/, internal/clients/, internal/oidc/, internal/mgmtapi/, internal/bff/]
promoted_to: null
openspec: changes/unify-consent-ledger
created: 2026-07-30
---

# Unify the consent ledger (plan)

> **Severity: HIGH.** Audit finding H6 —
> [`audit-2026-07-30-wiring-and-auth.md`](./audit-2026-07-30-wiring-and-auth.md).
> DAG child of `production-wiring-collapse`.
>
> **Pre-launch simplification (2026-07-30):** Harbor has **not launched** —
> there are no production rows and no users. So this is an **edit-in-place
> schema fix, not an expand/contract migration.** No new migration number, no
> backfill, no nullable-for-backcompat columns, no legacy-row handling. Amend
> the existing migrations directly and let a fresh `make migrate` produce the
> correct schema.

## Problem

There are **two parallel consent tables** with two independent code paths:

| Table | Migration | Domain type | Read/written by |
|---|---|---|---|
| `grants` | `0001_init` | `oidc.ConsentGrant` via `GrantStore` | `PPIDSessionResolver.Resolve`, `Service.issueRefreshToken`, `Service.Refresh`, `end_session` (`FindGrantByPPID`) |
| `consent_grants` | `0011_consent_grants` | `oidc.ConsentGrant` via `ConsentStore` | `mgmtapi` consent endpoints, `bff` dashboard, `Service.Authorize` consent check |

`DELETE /consent-grants/{client_id}` (`mgmtapi/consent.go:114-185`) revokes the
`consent_grants` row and cascades session revocation — but leaves the `grants`
row untouched. On the next `/authorize`, `PPIDSessionResolver.Resolve` finds the
surviving grant at `resolver.go:150-177` and returns `approved=true` **silently,
with no consent prompt**.

**The user's "disconnect this app" does not disconnect the app.** It revokes the
sessions, then re-grants on the next visit. Same for the dashboard's
`PostRevokeApp`.

The two tables also carry different data: `grants` holds `pairwise_sub` (the
PPID the RP sees) and `region`; `consent_grants` holds `granted_at`/`updated_at`
and a partial-unique active constraint. Neither is a superset.

Compounding it: `PPIDSessionResolver.Resolve` **auto-approves** — it always
returns `approved=true`. There is no consent ceremony at all, so any RP that gets
a user to `/authorize` silently obtains a grant. That is a separate gap, noted
here because it shares the code path; see *Open questions*.

## Proposed approach

Make `grants` the single ledger. It is the one the token path depends on and the
one that carries `pairwise_sub` — the field that must never change for a
(user, RP) pair (§3.2.3).

1. **Amend the existing migrations in place** (no new migration number):
   - `0001_init.up.sql` — add `updated_at timestamptz NOT NULL DEFAULT now()`
     to `grants`, the one column only `consent_grants` had. `created_at`,
     `revoked_at`, and the `(user_id, client_id)` unique index already exist.
   - `0011_consent_grants.up.sql` — **delete the migration entirely** (both
     `.up.sql` and `.down.sql`). It created the duplicate table; nothing should
     recreate it.
   - Renumbering the later migrations is optional and probably not worth the
     churn; leaving a gap at `0011` is fine (the tree already has one at `0014`).
     If you do renumber, do it in one commit and say so in the PR.

   No backfill: there are no rows. No expand/contract: there is no live table.
   The `.agents/db-migrate.md` ceremony exists for live schemas and does not
   apply pre-launch — state that in the PR description so a future reader does
   not mistake this for a shortcut.
2. **Collapse the interfaces.** `oidc.ConsentStore` and `oidc.GrantStore` become
   one. Prefer keeping `GrantStore`'s shape (it carries `PairwiseSub`) and adding
   the `List`/`Revoke`-by-id methods `ConsentStore` provides for the dashboard.
   Delete `clients.DBConsentStore`; extend `clients.DBGrantStore`.
3. **Repoint every caller**: `mgmtapi/consent.go`, `bff/dashboard.go`,
   `Service.Authorize`'s consent-decision block, `cmd/harbor-mgmt`'s
   `WithConsentStore`, and the export bundler
   (`identity/export.go:assembleConsent` reads `ListConsentGrantsByUser`).
4. **Preserve the escalation semantics** already in
   `PPIDSessionResolver.Resolve` (`resolver.go:162-176`): on a scope superset it
   revokes and re-creates with the union while **preserving `PairwiseSub`**.
   That behaviour must survive the merge exactly — a changed PPID would break
   every RP's notion of the user's identity.
5. **Verify the revoke path end-to-end**: revoke → next `/authorize` finds no
   grant → derives consent afresh. That is the acceptance test.

### Rejected alternative

*Keep both tables and dual-write.* Rejected: two writers to two tables with no
transaction spanning them is how the divergence arose. One ledger or none.

## DESIGN alignment

Serves §11.3 (user-initiated disconnect must actually disconnect), §3.2 (PPID
stability across re-authorization), §10 (data model — one user-owned consent row
per RP). No DESIGN change; the design describes one ledger, the code grew two.

## Target code paths

- `db/migrations/0001_init.up.sql` — add `updated_at` to `grants`
- `db/migrations/0011_consent_grants.{up,down}.sql` — **deleted**
- `db/queries/` — merge the consent queries into the grants queries; regenerate sqlc
- `internal/oidc/{consent,grants,service,resolver}.go` — one interface
- `internal/clients/{grants,consent}.go` — one store; delete `DBConsentStore`
- `internal/mgmtapi/consent.go`, `internal/bff/dashboard.go` — repoint
- `internal/identity/export.go` — DSAR bundle reads the unified table
- `cmd/harbor-mgmt/main.go` — one store wired

## Implementation checklist

- [ ] Add `updated_at` to `grants` in `0001_init.up.sql`; delete `0011_consent_grants.{up,down}.sql`
- [ ] Verify a from-scratch `make migrate` produces the intended schema, and `make migrate-down` unwinds cleanly
- [ ] Merge `ConsentStore` into `GrantStore`; delete the duplicate domain plumbing
- [ ] Regenerate sqlc (`make generate`); `make generate-check` clean
- [ ] Repoint mgmtapi, dashboard, `Service.Authorize`, export bundler, and both mains
- [ ] Preserve `PairwiseSub` across the scope-escalation revoke/re-create path
- [ ] Tests: **revoke via `DELETE /consent-grants/{client_id}` ⇒ the next `/authorize` has no grant** (the headline regression test for H6)
- [ ] Tests: same for the dashboard `PostRevokeApp` path
- [ ] Tests: PPID is byte-identical before and after a scope escalation
- [ ] Tests: DSAR export still lists consent grants after the merge
- [ ] Tests: session cascade on revoke still fires
- [ ] Author & verify paired OpenSpec change: `@openspec new unify-consent-ledger` then `openspec validate unify-consent-ledger --strict`
- [ ] Reconcile & promote: `@plan promote unify-consent-ledger`

## Risks & open questions

- **PPID stability is the sharp edge.** Any bug that regenerates `pairwise_sub`
  silently changes every affected user's `sub` at every RP. The golden-vector
  test for `DerivePPID` must be extended to cover the revoke→re-consent cycle.
- **No new migration number is taken**, so there is no collision risk with
  `refresh-session-claims` (which likewise amends an existing migration
  in place). Editing shipped migration files is safe **only** because Harbor
  has not launched — if that changes before this lands, stop and switch to a
  proper expand/contract migration.
- **Out of scope: the missing consent ceremony.** `Resolve` auto-approving is a
  real gap but it is a product/UX feature (a consent screen), not a data-model
  fix. File it as its own plan; do not smuggle a UI into this PR.
- `identity/export.go` reads `ListConsentGrantsByUser` — the DSAR bundle must not
  silently start returning an empty list.

## Definition of done

- Exactly one consent table and one store interface remain.
- Revoking consent through either surface means the next `/authorize` must
  re-consent, proven by test.
- PPIDs are unchanged across revoke/re-consent and scope escalation.
- `go build ./...`, `go vet ./...`, `go test ./...`, `make agent-check`,
  `make generate-check`, and the migration apply/rollback all green.
