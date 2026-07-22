# Proposal: TOTP / MFA second factor

## Problem

Harbor's `mfa_factors` DB table and full sqlc query set exist but the entire
service layer is missing. Users cannot enroll a TOTP app, the BFF login flow
has no step-up gate, and there are no recovery codes. A locked-out passkey
with no TOTP backup = permanently locked account.

## Proposed Solution

1. **`internal/mfa/TOTPService`** — pure service: `Enroll` (generate secret,
   encrypt under user DEK, return QR provisioning URI + 8 recovery codes),
   `Verify` (±1 step drift window, replay prevention), `VerifyRecovery`
   (burn-on-use bcrypt), `Delete`, `ListFactors`.

2. **BFF step-up gate** — after passkey assertion, check for active TOTP
   factors; set `BFFSessionRecord.PendingMFA = true` and redirect to
   `/mfa/verify` before completing the BFF session.

3. **Management API** — `POST /mfa/enroll`, `GET /mfa/factors`,
   `DELETE /mfa/factors/{id}`, `POST /mfa/verify` in `internal/mgmtapi/`.

4. **Recovery codes** — 8 × 8-char random codes, bcrypt-hashed (cost 12),
   stored as `type="recovery"` rows, burned on first use.

## Non-Goals

- FIDO2 step-up (separate feature)
- SMS OTP (not in DESIGN.md)
- ACR/AMR dynamic claims (follow-on: `acr-amr-dynamic`, gated on this feature)

## Success Criteria

- [ ] TOTP enrollment generates a working provisioning URI
- [ ] Verification with valid code succeeds; replay rejected
- [ ] BFF step-up gate fires when user has an active TOTP factor
- [ ] Recovery codes can be used once
- [ ] `go build/vet/test ./...` green
