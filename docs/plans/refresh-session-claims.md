---
title: Persist auth_time / acr / amr so refreshed tokens stop lying
status: draft
design_refs: [§3.5, §10, §3.1]
targets: [db/migrations/, db/queries/, internal/clients/, internal/oidc/]
promoted_to: null
openspec: changes/refresh-session-claims
created: 2026-07-30
---

# Persist auth_time / acr / amr on refresh sessions (plan)

> **Severity: MEDIUM.** Audit finding M3 —
> [`audit-2026-07-30-wiring-and-auth.md`](./audit-2026-07-30-wiring-and-auth.md).
> DAG child of `production-wiring-collapse` (refresh sessions are not persisted
> at all until that lands).
>
> **Pre-launch simplification (2026-07-30):** Harbor has **not launched** —
> there are no production rows and no users. So this is an **edit-in-place
> schema fix, not an additive migration.** No new migration number, no nullable
> columns for backward compatibility, and no NULL-`auth_time` handling: add the
> columns as `NOT NULL` directly to `0002_auth_tables.up.sql`, where `sessions`
> is created.

## Problem

`oidc.RefreshSession` carries `AuthTime int64`, `ACR string`, and `AMR []string`
(`internal/oidc/refresh.go:36-38`), and `Service.Refresh` faithfully passes them
into `IssueParams` (`service.go:718-722`). But:

1. The `sessions` table has **no `auth_time`, `acr`, or `amr` columns** —
   migrations `0002`, `0005`, `0007` add `client_id` and `grant_id` and nothing
   else.
2. `buildCreateSessionParams` (`clients/sessions.go:89-125`) never writes them.
3. `rowToRefreshSession` (`clients/sessions.go:294-317`) never reads them.

So on every refresh, `session.AuthTime` is `0` and ACR/AMR are empty. The
re-issued ID token claims **`auth_time: 0`** — 1970-01-01 — and silently drops
the ACR/AMR claims that record *how* the user authenticated.

Impact: any RP enforcing `max_age` gets a false answer (a session that
authenticated 10 seconds ago looks 56 years stale, or, depending on the
comparison, trivially passes). Any RP relying on `acr`/`amr` to distinguish
passkey-only from passkey+TOTP loses that signal exactly when it matters — on
long-lived sessions.

`InMemorySessionStore` round-trips these fields correctly, which is precisely why
the 45k-LOC test suite never caught it: the DB store is the only implementation
that drops them, and it is the one production uses.

`RotateSession` propagates the same emptiness forward (`service.go:771-783`
copies `session.AuthTime/ACR/AMR` into `newSession`), so once wrong, always wrong
for the life of the session family.

## Proposed approach

1. **Amend `0002_auth_tables.up.sql` in place** — add three columns to the
   `sessions` table where it is created, all `NOT NULL`:
   - `auth_time timestamptz NOT NULL`
   - `acr text NOT NULL DEFAULT ''`
   - `amr text[] NOT NULL DEFAULT '{}'`

   `NOT NULL` is the right call pre-launch: there are no legacy rows, so the
   "NULL means we don't know" case that would otherwise force fail-closed claim
   omission (see step 4) **cannot arise**, and the DB enforces the invariant the
   domain type already assumes.

   Store `auth_time` as `timestamptz`, not a bare integer: the rest of the
   schema is timestamptz throughout, and converting to Unix seconds at the
   domain edge (as `AuthCode.AuthTime` already does) keeps the DB honest.

2. **Write path** — `buildCreateSessionParams` populates all three from the
   domain type. Used by both `CreateSession` and `RotateSession`, so the two
   paths cannot diverge (that shared-builder property is already why the file is
   structured this way — preserve it).

3. **Read path** — `rowToRefreshSession` populates all three, converting
   `auth_time` to Unix seconds for the domain type.

4. **Fail-closed on a zero value.** With `NOT NULL` columns the "unknown"
   case is gone at the DB layer, but keep the guard at the issuer: if
   `AuthTime` is somehow zero, `JWTIssuer` should **omit** the `auth_time`
   claim rather than assert 1970-01-01. This matches
   `MapAuthMethodToACRAMR`'s existing fail-closed convention
   (`oidc/auth_method.go` — an unknown method emits *no* ACR/AMR rather than a
   lie). `AuthTime` is currently unconditional at `jwt_issuer.go:103`. Cheap
   insurance against a future code path that forgets to set it.

5. Regenerate sqlc and update the `sessions` queries in `db/queries/`.

## DESIGN alignment

Serves §3.5 (refresh-token rotation preserves the original authentication
context), §10 (data model — the session row is the durable record of that
context), §3.1 (ACR/AMR distinguish passkey from passkey+TOTP). No DESIGN change:
the design already specifies these claims; the storage layer just never carried
them.

## Target code paths

- `db/migrations/0002_auth_tables.up.sql` — three columns on `sessions`
- `db/queries/sessions.sql` — add the columns to insert/select; regenerate sqlc
- `internal/clients/sessions.go` — `buildCreateSessionParams` + `rowToRefreshSession`
- `internal/oidc/jwt_issuer.go` — omit `auth_time` when unknown (fail closed)
- `internal/oidc/service.go` — confirm `RotateSession` propagation is now meaningful

## Implementation checklist

- [ ] Add `auth_time` / `acr` / `amr` to `sessions` in `0002_auth_tables.up.sql` (`NOT NULL`)
- [ ] Verify a from-scratch `make migrate` produces the intended schema, and `make migrate-down` unwinds cleanly
- [ ] `db/queries/sessions.sql` updated; `make generate` + `make generate-check` clean
- [ ] `buildCreateSessionParams` writes `auth_time`/`acr`/`amr`
- [ ] `rowToRefreshSession` reads them back, converting to Unix seconds
- [ ] `JWTIssuer` omits `auth_time` (and ACR/AMR) when unknown rather than emitting `0`
- [ ] Tests: **round-trip through the real DB store** — create → read → the three fields survive (this is the test whose absence caused the bug)
- [ ] Tests: `/token` → `/token` (refresh) ⇒ the refreshed ID token's `auth_time` equals the original authentication time, not `0`
- [ ] Tests: ACR/AMR survive a full rotation chain (issue → refresh → refresh)
- [ ] Tests: a zero `AuthTime` reaching `JWTIssuer` omits the claim rather than asserting `0`
- [ ] Tests: `max_age` semantics behave correctly against a refreshed token
- [ ] Author & verify paired OpenSpec change: `@openspec new refresh-session-claims` then `openspec validate refresh-session-claims --strict`
- [ ] Reconcile & promote: `@plan promote refresh-session-claims`

## Risks & open questions

- **No new migration number is taken**, so there is no collision risk with
  `unify-consent-ledger` (which likewise amends existing migrations in place).
  Editing shipped migration files is safe **only** because Harbor has not
  launched — if that changes before this lands, stop and switch to a proper
  additive migration.
- **Omitting `auth_time` is a spec judgement.** OIDC Core makes `auth_time`
  REQUIRED when `max_age` was requested and OPTIONAL otherwise. Omitting is
  correct for the optional case; if `max_age` was requested and we have no
  recorded time, the right answer is to **refuse the refresh**, not to guess.
  Confirm that reading before implementing.
- This feature is small and self-contained — a good candidate to land early in
  its wave. It shares no files with its sibling children except the migration
  directory.

## Definition of done

- `auth_time`, `acr`, and `amr` survive a create→read→rotate cycle through the
  real DB store.
- No refreshed token ever carries `auth_time: 0`.
- `go build ./...`, `go vet ./...`, `go test ./...`, `make agent-check`,
  `make generate-check`, and migration apply/rollback all green.
