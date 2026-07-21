# Tasks: KMS provider integration (real regional KEK)

## Prerequisites

- [ ] `envelope-encryption-kms` is on `main` (the `KeyProvider` seam, dev
  `localKeyProvider`, and the `kmsKeyProvider` scaffold this change replaces).
  No other hard dependency — this is a self-contained `internal/crypto/` change
  with no hot-path contention and no migrations.

## Implementation

- [ ] `internal/crypto/kmsclient.go`: define the narrow `kmsClient` seam
  (`Encrypt(ctx, keyID, plaintext) ([]byte, error)` /
  `Decrypt(ctx, keyID, ciphertext) ([]byte, error)`) + an in-process **fake**
  for hermetic tests.
- [ ] `internal/crypto/keyprovider_kms.go`: implement `kmsKeyProvider.WrapDEK` —
  resolve `region` → KEK key-ID; `kmsClient.Encrypt`; emit a versioned envelope
  (`version`, `region`, `kek_key_id`, ciphertext).
- [ ] Implement `kmsKeyProvider.UnwrapDEK` — parse+validate the envelope header
  (region + key-ID MUST match the caller's `region`); `kmsClient.Decrypt`;
  return `DEK`. Mismatch/parse failure → generic fail-closed error.
- [ ] Implement `RewrapDEK(ctx, region, wrapped)` — unwrap under the header KEK,
  re-wrap under the region's current KEK key-ID; DEK plaintext stays in the
  transient window only.
- [ ] Region→key-ID resolution via injected config; unknown region fails closed,
  never falls back to another region's KEK.
- [ ] Preserve fail-closed posture: no panics; keep `ErrKMSNotImplemented` for
  the genuinely-unconfigured case; unwrap errors are generic (no oracle signal).
- [ ] Keep the `KeyProvider` interface + all callers/wiring unchanged.

## Tests

- [ ] `internal/crypto/keyprovider_kms_test.go`: `WrapDEK`→`UnwrapDEK` round-trip
  against the fake `kmsClient`.
- [ ] Wrong-region unwrap rejected (fail closed, generic error).
- [ ] Tampered envelope header rejected (fail closed).
- [ ] `RewrapDEK` yields a DEK-preserving re-wrap under the new KEK.
- [ ] Unknown-region wrap/unwrap fails closed; no cross-region KEK fallback.
- [ ] No panic on any malformed/short input.
- [ ] Integration lane: Docker-Compose KMS emulator (e.g. LocalStack KMS)
  exercises the real vendor-adapter `kmsClient` path.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate kms-provider-integration --strict`
