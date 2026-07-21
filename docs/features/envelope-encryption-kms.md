---
title: Envelope Encryption & KMS (per-user DEK / regional KEK)
status: implemented
design_refs: [§4.4, §7.3, §10]
code:  [internal/crypto/]
spec:  []
tests: [internal/crypto/]
depends_on: []
plan: envelope-encryption-kms
last_reconciled: 2026-07-21
---

# Envelope Encryption & KMS (per-user DEK / regional KEK)

## Summary

`internal/crypto` is the envelope-encryption foundation every 🔒 column in the
data model (§10) sits on — `users.dek_wrapped`, `users.pairwise_secret`,
`credentials.password_hash`, `mfa_factors.secret`. It implements docs/DESIGN.md
§4.4: per-user **Data Encryption Keys (DEKs)** protect column plaintext under
AES-256-GCM, and each DEK is itself **wrapped under a regional Key Encryption
Key (KEK)** through a narrow `KeyProvider` seam. The DEK exists in memory only
transiently; at rest we store only the KEK-wrapped DEK — which makes
**crypto-shred** erasure (§11.6) a one-delete operation: destroy
`users.dek_wrapped` and every column encrypted under it becomes permanently
unrecoverable, even against immutable backups. The production KEK path is a
documented HSM scaffold (see Known gaps); the dev path is a self-identifying
HKDF provider that refuses to run without a secret.

## Behavior (as-built)

**AES-256-GCM (`Encryptor`/`Decryptor`)** — authenticated encryption over a
per-user DEK. Each message carries a fresh CSPRNG nonce; decryption **fails
closed** — any tag mismatch, tampered ciphertext, wrong AAD, wrong region, or
short input returns the single generic `ErrDecryptFailed`, never partial
plaintext. Collapsing all failure modes into one error denies a
decryption-oracle attacker any signal about *which* check failed.

**DEK generation** — `GenerateDEK` draws a 256-bit key from the system CSPRNG
and returns `ErrRandFailure` if the RNG fails or returns a degenerate
(all-zero) value, so a broken RNG can never yield a predictable key.

**`KeyProvider` (KEK wrap/unwrap)** — the DEK-wrapping seam, region-threaded so
a wrap/unwrap never crosses a jurisdiction (§5.4):

- `WrapDEK(ctx, region, dek) ([]byte, error)`
- `UnwrapDEK(ctx, region, wrapped) (DEK, error)`

Two implementations behind that one interface:

- **`localKeyProvider` (dev/test)** — derives the KEK from an env-supplied
  secret via HKDF. Deterministic, hermetic, self-identifying, and **refuses to
  construct on an empty secret** (`ErrEmptySecret`) so it can never be mistaken
  for a production provider.
- **`kmsKeyProvider` (prod, scaffold)** — the interface contract is complete so
  callers and wiring can reference it, but the regional KMS/HSM integration is
  deferred. Both methods return `ErrKMSNotImplemented` (fail closed) rather than
  panicking, so a misconfigured prod deployment degrades gracefully instead of
  crashing.

**Crypto-shred** — erasure is implemented as *destroying the wrapped DEK*.
Because the column plaintext is only recoverable via the DEK, and the DEK only
via its wrapped form, deleting `users.dek_wrapped` renders every dependent
ciphertext unrecoverable — satisfying GDPR erasure even against append-only
backups (§11.6). The pattern is documented and covered by a test that proves
ciphertext is unrecoverable after the wrapped DEK is gone.

## Interfaces / Endpoints

No HTTP surface — this is a pure crypto library. Exported Go surface:

- `crypto.GenerateDEK() (crypto.DEK, error)`
- `crypto.Encryptor` / `crypto.Decryptor` — AES-256-GCM over a `DEK`
  (nonce‖ciphertext‖tag; decrypt fails closed → `ErrDecryptFailed`).
- `crypto.KeyProvider` — `WrapDEK(ctx, region, DEK) ([]byte, error)` /
  `UnwrapDEK(ctx, region, []byte) (DEK, error)`.
- `crypto.NewLocalKeyProvider(secret ...)` — dev-only HKDF provider;
  `ErrEmptySecret` on an empty secret.
- Sentinel errors: `ErrDecryptFailed`, `ErrRandFailure`, `ErrEmptySecret`,
  `ErrKMSNotImplemented`.

## Code map

| Path | Role |
|---|---|
| `internal/crypto/envelope.go` | `Encryptor`/`Decryptor` (AES-256-GCM, per-message CSPRNG nonce, fail-closed), `GenerateDEK`. |
| `internal/crypto/keyprovider.go` | `KeyProvider` interface + dev `localKeyProvider` (HKDF from env secret; refuses empty secret). |
| `internal/crypto/keyprovider_kms.go` | `kmsKeyProvider` production **scaffold** — HSM boundary documented; methods return `ErrKMSNotImplemented`. |
| `internal/crypto/errors.go` | Generic `ErrDecryptFailed` (decryption-oracle defense) + `ErrRandFailure`, `ErrEmptySecret`, `ErrKMSNotImplemented`. |
| `internal/crypto/envelope_test.go`, `keyprovider_test.go` | Round-trip, tamper/fail-closed, wrong-region rejection, wrap/unwrap identity, crypto-shred unrecoverability. |
| `internal/crypto/envelope_vectors_test.go` | Frozen golden GCM vectors (byte-equality; RNG injected so vectors are reproducible without deterministic production nonces). |

## Security & privacy invariants

- **Fail-closed decryption (§4.4)** — every decrypt failure returns the single
  generic `ErrDecryptFailed`; no partial plaintext, no oracle signal.
- **Envelope separation (§4.4, §7.3)** — column plaintext is encrypted under a
  per-user DEK; the DEK is stored only KEK-wrapped. The KEK never leaves the
  HSM boundary in the (scaffolded) production provider.
- **Crypto-shred erasure (§11.6)** — destroying the wrapped DEK is sufficient
  and irreversible erasure of all dependent columns; tested.
- **No cross-jurisdiction key ops (§5.4)** — `region` is threaded through every
  `WrapDEK`/`UnwrapDEK` call.
- **Dev provider is unmistakable** — `localKeyProvider` is self-identifying and
  refuses to run without a secret (`ErrEmptySecret`); it cannot silently stand
  in for prod.
- **CSPRNG integrity** — `GenerateDEK` rejects RNG failure / degenerate output
  (`ErrRandFailure`).

## Tests

`internal/crypto/` — AES-256-GCM encrypt→decrypt round-trip; tamper detection
(flipped byte / wrong tag → `ErrDecryptFailed`); wrong-region unwrap rejection;
`WrapDEK`→`UnwrapDEK` identity; empty-secret `localKeyProvider` construction
rejected; crypto-shred renders ciphertext unrecoverable once the wrapped DEK is
gone; **frozen golden vectors** (`envelope_vectors_test.go`) byte-match with an
injected RNG. `go test ./internal/crypto/...` green.

## Known gaps / TODOs

- **`kmsKeyProvider` is a SCAFFOLD** — the regional KMS/HSM wrap/unwrap
  integration is deferred; both methods return `ErrKMSNotImplemented` and fail
  closed. This must be implemented before any production deployment that stores
  real encrypted rows; the dev `localKeyProvider` is **not** production-safe.
- **KEK rotation** — re-wrapping DEKs when a KEK rotates is out of scope for
  v1; the seam is documented but not built.
- **Golden-vector nonce injection** — GCM vectors pin the nonce via an injected
  RNG in the test harness only; production nonces remain per-message CSPRNG.
