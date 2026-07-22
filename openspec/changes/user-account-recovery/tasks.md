# Tasks: User account recovery (fail-closed Phase 1)

## Prerequisites

- [ ] Depends on the shipped passkey/enrollment stack (`user-enrollment` ✅,
  `webauthn-session-store` ✅) and shipped envelope/hash-at-rest conventions
  (`envelope-encryption-kms` ✅). Lands after the Gate-1 guardrails
  (`regional-data-residency-routing`, `observability-metrics`).
- [ ] **Migration prefix `0015` is reserved** for this change
  (`db/migrations/0015_recovery_codes.up.sql` / `.down.sql`). Do not reuse
  `0015` elsewhere (consent-ledger 0011, dynamic-client-registration 0012,
  user-audit-trail 0013, email-relay-service 0016).

## Implementation

- [ ] Migration `0015_recovery_codes` (up/down): `recovery_codes(user_id,
  code_hash, used_at, created_at)`, index on `(user_id)`, unique
  `(user_id, code_hash)`.
- [ ] `db/queries/recovery_codes.sql` + `make codegen`: insert-batch, atomic
  consume-by-hash (only if `used_at IS NULL`), count-unused.
- [ ] `internal/identity/recovery.go`: generate N single-use codes with **≥128
  bits of entropy each** (so salted SHA-256 at rest is adequate); salted
  SHA-256 hash at rest; show plaintext once; single-use consume;
  `recovery_required` lifecycle.
- [ ] `internal/webauthn/`: register additional passkey / hardware key as a
  fallback recovery factor (reuse the shipped registration path).
- [ ] `internal/mgmtapi/recovery.go`: user endpoints — generate/regenerate
  codes, begin/complete recovery, list registered factors.
- [ ] Recovery ceremony: accept a valid unused code **or** a fallback
  authenticator → a **scoped enrollment-only session** that may ONLY enroll a
  fresh passkey (no consent dashboard, no compliance export, no email change,
  no other authenticated surface); require the fresh passkey enrollment before
  clearing `recovery_required`.
- [ ] Per-user recovery attempt lockout stored in the **regional DB** (not in
  metrics/counters); enforce region-pinning on all recovery reads/writes.
- [ ] Rate-limit, region-pin, and meter (aggregate-only) recovery attempts;
  emit `user-audit-trail` events (begin / success / failure).

## Tests

- [ ] A recovery code is single-use — replay/consume-twice is rejected
  (atomic).
- [ ] Only a salted hash is stored; the plaintext code is never persisted.
- [ ] Losing one factor does not lock the account — a fallback authenticator
  recovers.
- [ ] The account stays `recovery_required` until a fresh passkey is enrolled.
- [ ] The post-ceremony session is scoped enrollment-only — attempting any
  non-enrollment surface (consent dashboard, export, email change) is denied
  until `recovery_required` is cleared.
- [ ] Recovery codes carry ≥128 bits of entropy; per-user attempt lockout is
  enforced from DB state (not derived from metrics).
- [ ] An invalid / exhausted code fails closed (grants nothing).
- [ ] Security: recovery secrets are not operator-readable; recovery is
  rate-limited; no cross-user code satisfies another user; endpoints don't leak
  existence.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate user-account-recovery --strict`
