# Design: TOTP / MFA second factor

## Architecture

```
  [harbor-mgmt BFF]
       │
       ▼
  PasskeyAssertion OK
       │
       ▼
  MFAStepUpCheck(ctx, userID, bffSession)
  ├── ListFactors() == [] ──► SetUser() ──► issue BFF session (normal)
  └── active TOTP factor found
           └── PendingMFA = true
               └── redirect to /mfa/verify
                        │
                        ▼
               POST /mfa/verify { code }
                        │
                        ▼
               TOTPService.Verify(ctx, userID, code)
                        │
                        ▼
               SetUser() ──► issue BFF session (step-up complete)
```

## Key types

### `internal/mfa/service.go`

```go
type Factor struct {
    ID        string
    UserID    string
    Type      string   // "totp" | "recovery"
    CreatedAt time.Time
    Used      bool     // only meaningful for recovery codes
}

type EnrollResult struct {
    FactorID      string
    ProvisionURI  string   // otpauth://totp/...
    RecoveryCodes []string // 8 plain-text codes, shown once
}

type TOTPService struct {
    q      mfaQuerier
    cipher crypto.Encryptor
    keys   crypto.KeyProvider
    now    func() time.Time
}
```

## Crypto pattern for TOTP secret

```
dek = KeyProvider.UnwrapDEK(ctx, region, user.dek_wrapped)
secret = Cipher.Encrypt(dek, rawTOTPSecret, []byte("harbor-mfa-totp-v1:"+userID))
store in mfa_factors.secret
```

Decryption on verify reverses this. The AAD binds the blob to the user.

## TOTP parameters

- Algorithm: HMAC-SHA1 (RFC 6238 default, widest authenticator compat)
- Period: 30s
- Digits: 6
- Drift window: ±1 step (tolerates ±30s clock skew)
- Replay prevention: store last-verified counter per factor in a Redis key
  (`totp:used:{factorID}:{counter}` with TTL = 2× period = 60s)

## Recovery codes

- 8 codes × 8 random alphanumeric chars = ~47 bits of entropy each
- Stored as bcrypt hash (cost 12) in `mfa_factors.code_hash`
- `mfa_factors.used = true` after first use (`MarkMFAFactorUsed`)
- Never re-displayed after enrollment

## BFF session record change

```go
type BFFSessionRecord struct {
    // ... existing fields ...
    PendingMFA bool  // true = user must complete TOTP before session is valid
}
```

The BFF auth source checks `PendingMFA` and rejects the `/callback` if still
true — the step-up must be completed via `/mfa/verify`.
