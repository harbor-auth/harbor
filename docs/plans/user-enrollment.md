---
title: User creation & enrollment (§11.1 signup flow)
status: promoted
design_refs: [§11.1, §10, §4.4]
targets: [internal/identity/, internal/webauthn/, cmd/harbor-mgmt/, db/queries/]
promoted_to: docs/features/user-enrollment.md
openspec: changes/user-enrollment
created: 2026-07-10
---

# User creation & enrollment (plan)

> **Dependency order:** depends on **`envelope-encryption-kms`** (needs a DEK to
> wrap `pairwise_secret` and to encrypt secret columns). Build *after* that root
> lands. `session-ppid-seam` in turn depends on this (it needs a real user row
> with a `pairwise_secret` to derive a PPID).

## Problem

There is no real signup. `internal/webauthn` runs correct passkey ceremonies but
reads the `user_id` from an **insecure dev-only query param** — no `users` row is
created, no home region is assigned, no `pairwise_secret` or DEK is generated,
nothing is written to the `users` table. Without enrollment there is no user to
log in, no `pairwise_secret` for PPID derivation (§3.2), and no encrypted
account at all (§10). This is the front door, and it's currently a stub.

## Proposed approach

Implement the §11.1 enrollment sequence in the management plane
(`cmd/harbor-mgmt`, §4.1 cold path):

1. **Choose home region** at signup; encode it into the user id (region-prefixed
   externally) so all future routing needs no global lookup (§3.4, §5).
2. **Create the `users` row** — `id`, `region`, `status='active'`, and the two
   🔒 secrets:
   - **`pairwise_secret`** — CSPRNG, used only for PPID derivation (§3.2).
   - **`dek_wrapped`** — a fresh DEK (`crypto.GenerateDEK`) wrapped by the
     regional KEK (`crypto.KeyProvider.WrapDEK`, from `envelope-encryption-kms`).
   The `pairwise_secret` is stored encrypted under that DEK.
3. **Register the first passkey** via the existing
   `webauthn.BeginRegistration/FinishRegistration`, now keyed off the real
   `users.id` instead of the query-param path. Persist the credential to the
   `credentials` table (replacing any in-memory store).
4. **Prompt recovery setup** (≥2 methods; §7.2) — v1 records the requirement and
   the recovery-code path; full social recovery is deferred.
5. **Remove the insecure dev-only `user_id` query-param path.**

## DESIGN alignment

Realizes §11.1 (enrollment: region choice, passkey, `pairwise_secret` + DEK
wrapped by regional KEK) and the `users`/`credentials` tables in §10. Depends on
§4.4 envelope encryption. Does **not** change `DESIGN.md`.

## Target code paths

- `db/queries/users.sql` — `CreateUser`, `GetUser`, `SetStatus` (regen `internal/gen/db`)
- `internal/identity/enroll.go` — enrollment orchestration (region, secrets, DEK)
- `internal/webauthn/store.go` — sqlc-backed credential store (replace in-memory)
- `cmd/harbor-mgmt/main.go` — real signup endpoint; delete the dev-only user_id path
- `internal/identity/enroll_test.go`, `internal/webauthn/store_test.go`

## Implementation checklist

- [ ] `db/queries/users.sql` (`CreateUser`, `GetUser`, `SetStatus`); regenerate sqlc.
- [ ] Region selection + region-encoded user id (reuse `internal/region`).
- [ ] Generate `pairwise_secret` (CSPRNG) and DEK; wrap DEK via `crypto.KeyProvider`; encrypt `pairwise_secret` under the DEK.
- [ ] `CreateUser` writes the row (region + both 🔒 columns) atomically.
- [ ] sqlc-backed `webauthn.Store` (credentials table) replacing the in-memory store.
- [ ] First-passkey registration keyed off the real `users.id`.
- [ ] Delete the insecure dev-only `user_id` query-param path.
- [ ] Tests: enrollment creates exactly one row with region + wrapped DEK + encrypted secret; passkey persists; re-enroll is rejected/idempotent as designed; **negative:** dev-only path is gone.
- [ ] Author & verify paired OpenSpec change: `openspec validate user-enrollment --strict`
- [ ] Reconcile & promote: `@plan promote user-enrollment`

## Risks & open questions

- **Recovery setup** (§7.2, ≥2 methods) is only partially in scope for v1 — record the requirement + recovery codes; defer social recovery to its own plan.
- Enrollment writes multiple rows (user + credential) — must be transactional so a half-enrolled account is impossible.
- Region assignment policy (user-chosen vs geo-inferred) needs a product decision — default to explicit user choice, encode into the id.

## Definition of done

`go build/vet/test ./...` green; a real signup creates a region-encoded `users`
row with a wrapped DEK + encrypted `pairwise_secret`, registers the first
passkey to the `credentials` table, and the insecure dev-only path is deleted;
`make agent-check` clean. Ready to `@plan promote`.
