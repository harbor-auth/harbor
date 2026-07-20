---
title: Grant-ID Foreign Key on Sessions (per-grant revocation scoping)
status: implemented
design_refs: [§3.5, §10, §11.3]
code:  [db/migrations/, db/queries/, internal/clients/, internal/oidc/]
spec:  []
tests: [internal/clients/]
depends_on: [oidc-authorization-code]
plan: grant-id-fk
last_reconciled: 2026-07-20
---

# Grant-ID Foreign Key on Sessions (per-grant revocation scoping)

## Summary

The `sessions` table now carries a `grant_id` foreign key to `grants(id)`, so
session revocation can be scoped to a single **user-client-grant family**
rather than every session for a `(user_id, client_id)` pair (docs/DESIGN.md
§3.5, §10, §11.3). This unblocks the §11.3 "disconnect a connected app" user
flow — a user can revoke one app's grant without logging themselves out of
other grants that happen to share the same client — and tightens theft-signal
scoping so future multi-grant scenarios revoke exactly the compromised family.

The column lands **nullable** (expand phase of the expand/contract migration
pattern, §1.8): sessions written before the column existed, and any write path
that omits `GrantID`, keep working. The FK to `grants(id)` is enforced from the
first migration; only the `NOT NULL` contract is deferred to a future phase.

## Behavior (as-built)

**Schema (`0007_sessions_grant_id`)** — adds `grant_id UUID REFERENCES
grants(id)` (nullable) plus a partial index `idx_sessions_grant_id ON sessions
(grant_id) WHERE revoked_at IS NULL`, which makes "find the active sessions for
this grant" an O(log n) lookup — the exact access pattern the revoke query
needs.

**Write path (`buildCreateSessionParams`)** — the old `TODO(grant-fk)` guard
that rejected any non-empty `GrantID` is gone. The domain `RefreshSession.GrantID`
is now mapped to `pgtype.UUID`: a non-empty value is parsed and stored; an
**empty string maps to SQL `NULL`** for backward compatibility with legacy
rows. The inverse (`nullableUUIDToString`) reads `NULL` back as `""`, so the
round-trip is lossless. `buildCreateSessionParams` is shared by both
`CreateSession` and `RotateSession`, so the two write paths cannot silently
diverge on how they persist the FK.

**Revocation (`RevokeSessionsByGrant`)** — a new `oidc.SessionStore` method
revokes all active sessions for one `grant_id`. It sits alongside the existing
family-revoke methods, each scoped differently:

| Method | Scope | Use |
|---|---|---|
| `RevokeSession` | one session | single logout |
| `RevokeSessionsByGrant` | one grant | disconnect one app (§11.3) |
| `RevokeSessionsByUserClient` | one `(user, client)` family | theft signal (§3.5) |
| `RevokeSessionsByUser` | all of a user's sessions | "sign out everywhere" |

Both `InMemorySessionStore` and `DBSessionStore` implement the new method; the
in-memory store filters by `grantID`, the DB store issues the new sqlc query.

## Interfaces / Endpoints

No HTTP surface. Exported Go surface:

- `oidc.SessionStore` gains `RevokeSessionsByGrant(ctx context.Context, grantID string) error`.
- `clients.DBSessionStore.RevokeSessionsByGrant` — DB implementation over the
  new `RevokeSessionsByGrant` sqlc query.
- `oidc.RefreshSession.GrantID` is now honoured end-to-end (previously always dropped).

## Code map

| Path | Role |
|---|---|
| `db/migrations/0007_sessions_grant_id.{up,down}.sql` | Adds nullable `grant_id` FK + partial active-session index. |
| `db/queries/sessions.sql` | `grant_id` in the `CreateSession` INSERT; new `RevokeSessionsByGrant` DELETE/UPDATE. |
| `internal/gen/db/sessions.sql.go` | Regenerated sqlc output. |
| `internal/clients/sessions.go` | `buildCreateSessionParams` maps `GrantID` (empty→NULL); `RevokeSessionsByGrant`; `nullableUUIDToString`. |
| `internal/oidc/refresh.go` | `SessionStore` interface extended with `RevokeSessionsByGrant`; `InMemorySessionStore` impl; threads `GrantID` through `RotateSession`; removed the `TODO(grant-fk)` note. |

## Security & privacy invariants

- **Nullable-first migration (§1.8)** — the column is additive and nullable so
  a rolling deploy never breaks in-flight writers; the FK is enforced from day
  one, the `NOT NULL` contract is a later phase after backfill.
- **Least-scope revocation (§3.5, §11.3)** — per-grant revocation revokes
  exactly the compromised/disconnected family, avoiding the collateral logout
  of unrelated sessions that share a `(user, client)` pair.
- **Lossless NULL round-trip** — empty `GrantID` ↔ SQL `NULL` ↔ empty `GrantID`,
  so legacy rows are indistinguishable from "no grant" without a data-migration
  surprise.
- **No PII in the FK** — `grant_id` is an opaque UUID; no user-identifying data
  is added to the session row.

## Tests

- `internal/clients/sessions_test.go` — `RevokeSessionsByGrant` revokes only
  the matching grant's sessions; `buildCreateSessionParams` maps a populated
  `GrantID` to a valid `pgtype.UUID` and an empty `GrantID` to SQL `NULL`;
  `nullableUUIDToString` round-trips `NULL` back to `""`.
- In-memory `SessionStore` conformance for the new method.

## Known gaps / TODOs

- **`grant_id` is still nullable** — the `NOT NULL` contract phase (§1.8
  contract migration) is deferred until every write path populates the column
  and existing rows are backfilled. Until then, a session with a `NULL`
  `grant_id` cannot be revoked via `RevokeSessionsByGrant`.
- **Consent-time population** — the FK is only as useful as the write paths
  that set it; wiring `RefreshSession.GrantID` at consent time is tracked by
  the `session-ppid-seam` / `client-grant-persistence` work.

## As-built note

Migration landed as `0007_sessions_grant_id` (not the draft's `0003`) — it
merged after the recovery-required and interim migrations. Merged to `main` in
PR #30.
