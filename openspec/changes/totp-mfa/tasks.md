# Tasks: TOTP / MFA second factor

Estimated: ~8 hours. Parallelisable by Weft to ~3 hours.

## T1 — Dependencies (30 min)
- [ ] T1.1 `go get github.com/pquerna/otp/totp` and verify `go.mod`/`go.sum` updated
- [ ] T1.2 Verify `mfa_factors` sqlc queries compile: `go build ./internal/gen/db/...`

## T2 — `internal/mfa/service.go` (2 h)
- [ ] T2.1 Define `mfaQuerier` narrow interface (wraps sqlc `CreateMFAFactor`, `GetMFAFactor`, `ListMFAFactorsByUser`, `DeleteMFAFactor`, `MarkMFAFactorUsed`)
- [ ] T2.2 `NewTOTPService(q mfaQuerier, cipher crypto.Encryptor, keys crypto.KeyProvider) *TOTPService`
- [ ] T2.3 `Enroll(ctx, userID, region string) (EnrollResult, error)` — generate 20-byte secret, encrypt under DEK, store as `type="totp"`, generate 8 recovery codes (bcrypt cost 12), store as `type="recovery"`
- [ ] T2.4 `Verify(ctx, userID, code string) error` — decrypt secret, TOTP window check ±1 step, replay prevention
- [ ] T2.5 `VerifyRecovery(ctx, userID, code string) error` — list recovery codes, bcrypt compare, burn on match
- [ ] T2.6 `Delete(ctx, userID, factorID string) error` — verify ownership, delete row
- [ ] T2.7 `ListFactors(ctx, userID string) ([]Factor, error)`

## T3 — `internal/mfa/service_test.go` (1.5 h)
- [ ] T3.1 Fake `mfaQuerier` implementation
- [ ] T3.2 `TestTOTPEnroll_ReturnsProvisioningURI` — valid otpauth:// format
- [ ] T3.3 `TestTOTPVerify_ValidCode` — t-1, t, t+1 steps all pass
- [ ] T3.4 `TestTOTPVerify_ExpiredCode` — t-2, t+2 steps rejected
- [ ] T3.5 `TestTOTPVerify_Replay` — same code twice rejected
- [ ] T3.6 `TestTOTPVerify_WrongCode` — random 6-digit code rejected
- [ ] T3.7 `TestVerifyRecovery_BurnsOnUse` — second use returns ErrCodeAlreadyUsed

## T4 — BFF step-up gate (1 h)
- [ ] T4.1 Add `PendingMFA bool` to `bff.BFFSessionRecord` in `internal/bff/session.go`
- [ ] T4.2 `internal/bff/mfa_step_up.go`: `func CheckMFARequired(ctx, bffSession, mfaService) (required bool, err error)`
- [ ] T4.3 Wire into login handler: after assertion, call `CheckMFARequired`; if true, set `PendingMFA`, redirect to `/mfa/verify`
- [ ] T4.4 Auth source rejects `/callback` when `PendingMFA = true`

## T5 — Management API handlers (1.5 h)
- [ ] T5.1 `internal/mgmtapi/mfa.go`: `POST /mfa/enroll`, `GET /mfa/factors`, `DELETE /mfa/factors/{id}`, `POST /mfa/verify`
- [ ] T5.2 `internal/mgmtapi/mfa_test.go`: enroll → verify → delete flow; wrong code → 401; recovery code burn
- [ ] T5.3 Wire in `cmd/harbor-mgmt/main.go` with `TOTPService`

## T6 — Validation
- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
