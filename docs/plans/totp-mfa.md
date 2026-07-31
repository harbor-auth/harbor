---
title: TOTP / MFA second factor (§7.1)
status: planned
design_refs: [§7.1, §3.1, §3.3, §4.4]
targets: [internal/mfa/, internal/mgmtapi/, internal/bff/, cmd/harbor-mgmt/]
depends_on: [envelope-encryption-kms, webauthn-db-wiring]
wave: 6
priority: P1
created: 2026-07-22
---

# TOTP / MFA second factor (plan)

> **Priority:** Wave 6 P1. The `mfa_factors` schema is fully in place;
> this is a pure service + wiring build.

> ### ⚠️ Problem statement below is now STALE — 2026-07-30 audit
>
> The original problem ("nothing above the DB layer exists") **no longer
> holds**. `internal/mfa/` is now complete — `Service` with `Enroll`,
> `Activate`, `Verify`, `VerifyRecoveryCode`, `ListFactors`, `Disable`,
> `HasMFA`; envelope-encrypted secrets via `KeyResolver`; bcrypt recovery codes;
> `internal/mgmtapi/mfa.go` handlers; `bff.StepUpGate`; `bff.RecordTOTPStepUp`.
> All of it is written, tested, and wired into `cmd/harbor-mgmt`.
>
> **What is missing is enforcement** — audit finding **H7**
> ([`audit-2026-07-30-wiring-and-auth.md`](./audit-2026-07-30-wiring-and-auth.md)):
>
> 1. **MFA is inert.** `bff.StepUpGate` and `bff.RecordTOTPStepUp` are **never
>    called anywhere**. A successful `POST /mfa/verify`
>    (`internal/mgmtapi/mfa.go:181-200`) returns `{"status":"verified"}` and
>    **sets no session state whatsoever** — nothing writes `MFAVerifiedAt`, and
>    no endpoint reads it. `RecordTOTPStepUp`'s own doc comment admits it:
>    *"This is the intended call site for the deferred BFF TOTP step-up HTTP
>    handler. Until that handler is wired…"* — it never was. Enrolling TOTP
>    changes nothing about what an attacker with a session can do.
> 2. **TOTP is brute-forceable.** `mfa.Service.Verify` does a bare
>    `totp.Validate` with `totpSkew = 1` (a ~90 s acceptance window) and **no
>    attempt counter**. There is no rate limiter, because **harbor-mgmt has no
>    rate limiting on any endpoint** — the `RateLimitMiddleware` built for the
>    hot path is never applied to the cold path, and `WithRecoveryRateLimiter`
>    is never called either, so `/recovery/complete` is equally unlimited. Six
>    digits, ~90 s window, unlimited attempts.
>
>    `internal/identity/recovery.go` already implements exactly the right
>    pattern for recovery codes (`MaxFailedAttempts = 5`,
>    `LockoutDuration = 15m`, the `recovery_attempts` table). TOTP simply never
>    got it — reuse that shape rather than inventing a second one.
>
> **Revised scope:**
>
> - Add the missing BFF step-up handler that verifies **and records** — calling
>   `RecordTOTPStepUp` so both `MFAVerifiedAt` and `AuthMethod` (→ ACR/AMR) are
>   stamped.
> - Wire `bff.NewStepUpGate` in `cmd/harbor-mgmt` and apply `Require` to the
>   sensitive routes. **Proposed** initial set — confirm before building, since
>   over-gating makes the dashboard hostile: `POST /compliance/erase`
>   (irreversible), `POST /compliance/export` (full PII egress),
>   `DELETE /mfa/factors/{id}` (disabling the second factor),
>   `POST /recovery/codes`, `POST /dashboard/credentials/{id}/revoke`.
> - **Resolve the duplicate-verify ambiguity.** Two endpoints that both "verify
>   TOTP" but only one of which counts is precisely what produced this bug.
>   Either `PostMFAVerify` becomes the recorder, or it is deleted in favour of
>   the BFF handler. Pick one.
> - Per-account TOTP attempt counting + lockout (IP rate limiting alone is
>   insufficient — a distributed attacker rotates IPs; the *account* is the
>   thing under attack).
> - Apply `RateLimitMiddleware` to the cold path (`/mfa/verify`,
>   `/mfa/verify-recovery`, `/recovery/begin`, `/recovery/complete`, `/login`,
>   `/login/complete`, `/enroll`) and wire `WithRecoveryRateLimiter`.
>   `mgmtapi.Server.WriteRateLimited` already exists and meters correctly — it
>   has no caller.
>
> **Revised dependencies:** DAG child of
> [`production-wiring-collapse`](./production-wiring-collapse.md), and depends
> on [`fix-bff-session-binding`](./fix-bff-session-binding.md) — gating on a
> fixatable session would be theatre.
>
> **Note:** lockout is a DoS vector against the user (an attacker who knows a
> userID can lock them out for 15 minutes). `identity/recovery.go` already
> accepts that trade-off; be consistent, or prefer exponential backoff if the
> product view differs.
>
> **No migration** — reuse the existing `recovery_attempts` table. `0018` and
> `0019` are already claimed by `unify-consent-ledger` and
> `refresh-session-claims`.

## Problem

<!-- STALE as of 2026-07-30 — see the audit note above. Retained for provenance. -->


Harbor's DESIGN.md §7.1 names TOTP as the secondary/step-up factor for
users — and the DB schema is ready (`mfa_factors` table with full sqlc queries:
`CreateMFAFactor`, `GetMFAFactor`, `ListMFAFactorsByUser`, `DeleteMFAFactor`,
`MarkMFAFactorUsed`). But **nothing above the DB layer exists**:

- No `TOTPService` — no enrollment, verification, or deletion logic.
- No BFF step-up gate — the login flow issues a BFF session after passkey
  assertion regardless of whether the user has a TOTP factor registered.
- No recovery codes — a locked-out passkey + lost TOTP device = permanently
  locked account.
- No management API — users cannot enroll or delete TOTP factors.

The `type` column distinguishes `totp` secrets from `recovery` one-time codes.
The `secret` column holds an AES-GCM ciphertext: the TOTP shared secret
encrypted under the user's DEK (identical envelope-encryption pattern as
`pairwise_secret` in `identity.Enroll`).

## Proposed approach

### 1. `internal/mfa/` — pure service package

```go
type TOTPService struct {
    q       mfaQuerier   // narrow sqlc interface
    cipher  crypto.Encryptor
    keys    crypto.KeyProvider
    now     func() time.Time  // seam for test
}

// Enroll generates a new TOTP shared secret, encrypts it under the user DEK,
// stores it as mfa_factors row (type="totp"), and returns:
//   - the otpauth:// provisioning URI for QR display
//   - 8 recovery codes (8 chars each, bcrypt-hashed, stored as type="recovery")
func (s *TOTPService) Enroll(ctx context.Context, userID, region string) (EnrollResult, error)

// Verify checks a presented 6-digit code against all active TOTP factors for
// the user. Uses a ±1 step drift window (30s period, tolerates ±30s clock skew).
// Replay prevention: the (factor_id, code_counter) pair is stored; same code
// within the same window is rejected.
func (s *TOTPService) Verify(ctx context.Context, userID, code string) error

// VerifyRecovery checks a presented recovery code, burns it on first use
// (MarkMFAFactorUsed), and returns ErrCodeAlreadyUsed if replayed.
func (s *TOTPService) VerifyRecovery(ctx context.Context, userID, code string) error

// Delete removes a TOTP or recovery factor by ID.
func (s *TOTPService) Delete(ctx context.Context, userID, factorID string) error

// ListFactors returns all active (non-used) factors for a user.
func (s *TOTPService) ListFactors(ctx context.Context, userID string) ([]Factor, error)
```

**Crypto:** `crypto.Cipher.Encrypt(dek, totpSecret, aad)` where
`aad = []byte("harbor-mfa-totp-v1:" + userID)` — binding the ciphertext to
the user prevents cross-user blob substitution.

**TOTP library:** `github.com/pquerna/otp/totp` — already a well-audited Go
TOTP implementation; check `go.mod`, add if absent.

### 2. BFF step-up gate (`internal/bff/mfa_step_up.go`)

After passkey assertion succeeds in the login flow, before `BFFSessionStore.SetUser`
is called:

```
if user has active totp factors {
    set BFFSession.PendingMFA = true
    redirect to LOGIN_URL + /mfa/verify
} else {
    SetUser() → issue BFF session normally
}
```

Add `PendingMFA bool` to `bff.BFFSessionRecord`. The `/mfa/verify` handler
(in `harbor-mgmt`) calls `TOTPService.Verify`, then calls `BFFSessionStore.SetUser`
to complete the session.

### 3. Management API (`internal/mgmtapi/mfa.go`)

- `POST /mfa/enroll` — calls `TOTPService.Enroll`, returns provisioning URI +
  recovery codes (one-time display only).
- `GET /mfa/factors` — lists active factors.
- `DELETE /mfa/factors/{id}` — removes a factor.
- `POST /mfa/verify` — step-up verification during login (called from BFF).

### 4. Recovery codes

On `Enroll`, generate 8 random 8-character alphanumeric codes. Store each as a
separate `mfa_factors` row: `type="recovery"`, `code_hash=bcrypt(code)`,
`used=false`. `VerifyRecovery` iterates active recovery codes, bcrypt-compares
the presented code, burns on first match (`MarkMFAFactorUsed`), returns
`ErrCodeAlreadyUsed` on a used code.

## DESIGN alignment

Realises §7.1 (TOTP as secondary factor) and §4.4 (per-user DEK envelope
encryption for factor secrets). The step-up gate is §3.1 (auth flow). No
DESIGN.md changes needed.

## Target code paths

- `internal/mfa/service.go` — `TOTPService` + domain types
- `internal/mfa/service_test.go` — unit tests with fake querier
- `internal/mgmtapi/mfa.go` — REST handlers
- `internal/mgmtapi/mfa_test.go` — handler tests
- `internal/bff/mfa_step_up.go` — step-up gate
- `internal/bff/session.go` — add `PendingMFA bool` to `BFFSessionRecord`
- `cmd/harbor-mgmt/main.go` — wire `TOTPService` + handlers
- `go.mod` — add `github.com/pquerna/otp` if absent

## Implementation checklist

- [ ] T1: Add `github.com/pquerna/otp/totp` to `go.mod`/`go.sum` (`go get`)
- [ ] T2: `internal/mfa/service.go` — `TOTPService`, `Enroll`, `Verify`, `VerifyRecovery`, `Delete`, `ListFactors`
- [ ] T3: `internal/mfa/service_test.go` — fake querier; test drift window (t-1/t/t+1 pass; t-2 fail); test replay rejection; test recovery code burn
- [ ] T4: Add `PendingMFA bool` to `bff.BFFSessionRecord` in `internal/bff/session.go`
- [ ] T5: `internal/bff/mfa_step_up.go` — `MFAStepUpMiddleware` checks `PendingMFA` in session, redirects to `/mfa/verify` if true
- [ ] T6: `internal/mgmtapi/mfa.go` — `POST /mfa/enroll`, `GET /mfa/factors`, `DELETE /mfa/factors/{id}`, `POST /mfa/verify`
- [ ] T7: `internal/mgmtapi/mfa_test.go` — handler tests (enroll → verify → delete flow; wrong code → 401; recovery code burn)
- [ ] T8: `cmd/harbor-mgmt/main.go` — wire `TOTPService` + register mfa handlers
- [ ] T9: Verify `acr`/`amr` claims in `internal/oidc/token.go` are updated to reflect TOTP when it was the second factor (or mark as `acr-amr-dynamic` follow-on)
- [ ] Tests: `go build ./... && go vet ./... && go test ./...` green

## Risks

- **Clock skew** — TOTP is time-based; ensure server NTP is configured. The ±1
  step window covers ±30s of drift, which is standard.
- **Replay window** — a code is valid for up to 90s (±1 step × 30s). Store the
  last-used counter per factor to prevent same-code replay within the window.
- **Recovery code storage** — bcrypt cost 12 is correct for recovery codes (low
  entropy; machine-generated). Do NOT use SHA-256 (unlike `client_secret_hash`
  which has 256 bits of entropy).
- **Step-up gate completeness** — verify the gate fires for ALL login paths
  through the BFF, not just the passkey assertion handler.

## Definition of done

`go build/vet/test ./...` green; TOTP enrollment produces a working QR code;
verification with valid code succeeds and replay is rejected; the BFF step-up
gate redirects to `/mfa/verify` when a user has an active TOTP factor; recovery
codes can be used once; all factors can be deleted; no scaffold remains.
