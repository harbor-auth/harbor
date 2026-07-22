---
title: User account recovery (recovery codes & fallback factors, fail-closed)
status: draft
design_refs: [§11.7, §11.6, §4]
targets: [db/migrations/, internal/identity/, internal/webauthn/, internal/mgmtapi/]
promoted_to: null
openspec: changes/user-account-recovery
created: 2026-07-22
---

# User account recovery (plan)

> **Dependency order:** **Gate 2** of Wave 5 — depends on the shipped
> passkey/enrollment stack (`user-enrollment` ✅, `webauthn-session-store` ✅) and
> the shipped envelope crypto (`envelope-encryption-kms` ✅) for storing recovery
> secrets hashed/encrypted at rest. Lands **after** the Gate-1 guardrails
> (`regional-data-residency-routing`, `observability-metrics`). Scoped to a
> **safe Phase 1** — passkeys (add a second authenticator), one-time recovery
> codes, and hardware-key fallback; **social / M-of-N recovery is explicitly
> deferred** to a later wave.

## Problem

Harbor authenticates users with passkeys (§4). Passkeys are strong, but a user
who loses **all** their authenticators today has **no recovery path** — their
account is effectively lost. Account recovery is the single most dangerous
surface in any auth system: it is the attacker's favourite bypass, so it must be
built **fail-closed**, with recovery secrets never stored in a usable-by-the-
operator form, and every recovery attempt audited. There is a
`users.recovery_required` fail-closed guard already shipped (from the enrollment
work), but no actual recovery-factor storage or ceremony behind it.

## Proposed approach

Ship a **minimal, safe** recovery Phase 1.

1. **Recovery codes (`0015_recovery_codes`)** — at enrollment (or on demand),
   generate a set of **single-use** recovery codes. Store only a **hash** of
   each code (`SHA-256`, salted), never the plaintext — the plaintext is shown
   to the user exactly once. A consumed code is marked used and cannot be
   replayed.
2. **Fallback authenticators** — encourage/allow **multiple passkeys** and a
   **hardware security key** as independent recovery factors, so losing one
   device does not lock the account. This reuses the shipped WebAuthn
   registration path — a recovery factor is just an additional registered
   credential.
3. **Recovery ceremony (`internal/identity/` + `internal/mgmtapi/`)** — a
   user-authenticated ceremony: present a valid unused recovery code (or a
   registered fallback authenticator) → re-establish an authenticated session
   and **require** enrolling a fresh passkey before clearing
   `recovery_required`. The account stays fail-closed (`recovery_required`)
   until a new strong factor is in place.
4. **Rate-limited, audited, region-pinned** — recovery attempts are
   rate-limited (reuse `rate-limiting` posture), region-pinned
   (`regional-data-residency-routing`), metered aggregate-only
   (`observability-metrics`), and every attempt/success/failure emits a
   `user-audit-trail` event (`auth.recovery_*`).

## DESIGN alignment

Realises §11.7 (error/edge cases — the lost-authenticator recovery path) and
§4 (passkey lifecycle — multiple credentials, fresh-factor re-enrollment),
and leans on the §11.6 crypto model (recovery secrets are hashed/encrypted at
rest, never operator-readable). Does **not** change `DESIGN.md`. The
`recovery_required` fail-closed guard it completes is already in the design.

## Target code paths

- `db/migrations/0015_recovery_codes.up.sql` / `.down.sql` — `recovery_codes`
  table (`user_id`, `code_hash`, `used_at`, `created_at`).
- `db/queries/recovery_codes.sql` — insert-batch, consume-by-hash (atomic),
  count-unused.
- `internal/identity/recovery.go` — code generation, salted hashing,
  single-use consume, `recovery_required` lifecycle.
- `internal/webauthn/` — register an additional passkey / hardware key as a
  fallback factor (reuse the shipped registration path).
- `internal/mgmtapi/recovery.go` — user endpoints: generate/regenerate codes,
  begin/complete recovery, list registered factors.

## Implementation checklist

- [ ] Migration `0015_recovery_codes` (up/down): `recovery_codes(user_id, code_hash, used_at, created_at)`, index on `(user_id)`; unique `(user_id, code_hash)`.
- [ ] `db/queries/recovery_codes.sql` + `make codegen`: insert-batch, atomic consume-by-hash (only if unused), count-unused.
- [ ] Generate N single-use recovery codes; store only a **salted SHA-256 hash**; show plaintext to the user exactly once.
- [ ] Atomic single-use consume: a consumed code cannot be replayed; consuming is race-safe.
- [ ] Fallback authenticators: register additional passkey(s) / hardware key via the shipped WebAuthn path as independent recovery factors.
- [ ] Recovery ceremony: valid unused code **or** fallback authenticator → re-authenticated session; **require** enrolling a fresh passkey before clearing `recovery_required`.
- [ ] Recovery attempts rate-limited, region-pinned, and metered aggregate-only.
- [ ] Emit `user-audit-trail` events for recovery begin / success / failure.
- [ ] Tests: code is single-use (replay rejected); only a hash is stored (plaintext never persisted); losing one factor does not lock the account (fallback works); the account stays `recovery_required` until a fresh passkey is enrolled; an invalid/exhausted code fails closed.
- [ ] Tests (security): recovery secrets are not operator-readable; recovery attempts are rate-limited; no cross-user code satisfies another user.
- [ ] Author & verify paired OpenSpec change: `openspec validate user-account-recovery --strict`
- [ ] Reconcile & promote: `@plan promote user-account-recovery`

## Risks & open questions

- **Recovery is the #1 attack surface** — the whole ceremony must fail closed:
  an invalid/exhausted/replayed code grants nothing, and a successful recovery
  does **not** fully re-privilege the account until a fresh strong factor is
  enrolled. This is the load-bearing risk; it drives the `recovery_required`
  gating.
- **Code storage** — codes are hashed (salted SHA-256), never encrypted-
  reversibly and never plaintext; the operator must not be able to recover a
  usable code. Confirm the hash/salt matches the shipped hash-at-rest
  conventions.
- **Deferred social/M-of-N recovery** — explicitly out of scope for Phase 1;
  guardian/trusted-contact recovery is a larger design with its own threat model
  and is a later wave. Do not smuggle it in here.
- **Enumeration** — recovery endpoints must not reveal whether a
  user/code exists (uniform responses + rate limiting), to avoid an account/
  code oracle.

## Definition of done

`go build/vet/test ./...` green; a user who loses a device can recover via a
single-use recovery code or a registered fallback authenticator; recovery codes
are stored only as salted hashes (never plaintext, never operator-readable);
recovery is single-use, rate-limited, region-pinned, audited, and keeps the
account `recovery_required` until a fresh passkey is enrolled; social/M-of-N
recovery is **not** included; `make agent-check` clean. Ready to `@plan
promote`.
