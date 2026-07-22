# Proposal: User account recovery (fail-closed Phase 1)

## Problem

Harbor authenticates with passkeys (§4.4), but a user who loses **all** their
authenticators has **no recovery path** — the account is lost. Recovery is the
attacker's favourite bypass, so it must be fail-closed, store no
operator-usable secret, and audit every attempt. The shipped
`users.recovery_required` fail-closed guard exists, but there is no
recovery-factor storage or ceremony behind it.

## Proposed Solution

1. **Recovery codes (`0015_recovery_codes`)** — generate single-use codes;
   store only a **salted SHA-256 hash** (plaintext shown once, never persisted).
   A consumed code is marked used and cannot be replayed.
2. **Fallback authenticators** — allow multiple passkeys and a hardware key as
   independent recovery factors via the shipped WebAuthn registration path.
3. **Recovery ceremony** — a valid unused code or a fallback authenticator
   re-establishes an authenticated session but **requires enrolling a fresh
   passkey** before clearing `recovery_required`; the account stays fail-closed
   until a new strong factor is in place.
4. **Rate-limited, audited, region-pinned** — recovery is rate-limited,
   region-pinned, metered aggregate-only, and emits `user-audit-trail` events
   (`auth.recovery_begin` / `auth.recovery_succeeded` / `auth.recovery_failed`).

## Non-Goals

- Social / M-of-N / guardian recovery — deferred to a later wave (own threat
  model).
- Operator-initiated recovery or any operator-readable recovery secret —
  forbidden; the operator must never be able to recover an account.
- Email/SMS one-time-link recovery as a primary factor — out of scope for
  Phase 1 (and email is relay-masked; §7.5).
- Weakening `recovery_required` — recovery clears it only after a fresh passkey
  is enrolled.

## Success Criteria

- [ ] `recovery_codes` table (migration 0015): `user_id`, `code_hash`, `used_at`, `created_at`; unique `(user_id, code_hash)`.
- [ ] Codes are single-use; a replayed/consumed code is rejected; consume is atomic/race-safe.
- [ ] Only a **salted SHA-256 hash** is stored; plaintext is shown once and never persisted; secrets are not operator-readable.
- [ ] Fallback authenticators (additional passkey / hardware key) work as independent recovery factors.
- [ ] Recovery re-authenticates but keeps the account `recovery_required` until a fresh passkey is enrolled.
- [ ] Recovery is rate-limited, region-pinned, metered aggregate-only, and audited.
- [ ] No cross-user code satisfies another user; endpoints do not leak whether a user/code exists.
- [ ] Social/M-of-N recovery is **not** included.
- [ ] `make agent-check` clean.
