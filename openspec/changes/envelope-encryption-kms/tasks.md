# Tasks: Envelope encryption & KMS

## Prerequisites

- [ ] None — this is a foundational root of the build graph.

## Implementation

- [ ] `internal/crypto/envelope.go`: `Encryptor`/`Decryptor` (AES-256-GCM), `GenerateDEK`, fail-closed decrypt.
- [ ] `internal/crypto/keyprovider.go`: `KeyProvider` interface + `localKeyProvider` (HKDF from env secret; refuse empty secret).
- [ ] `internal/crypto/keyprovider_kms.go`: `kmsKeyProvider` scaffold documenting the HSM boundary (deferred impl).
- [ ] Crypto-shred helper / documented pattern (delete `dek_wrapped`).
- [ ] Region threaded through wrap/unwrap; wrong-region unwrap rejected.

## Tests

- [ ] Encrypt→decrypt round-trip; AAD binding.
- [ ] Tamper-detection: flipped byte ⇒ decrypt error (fail-closed).
- [ ] `GenerateDEK` uniqueness/length; wrap→unwrap identity.
- [ ] Wrong-region unwrap rejected; empty dev secret rejected.
- [ ] Crypto-shred: after deleting the wrapped DEK, ciphertext is unrecoverable.
- [ ] Frozen golden vectors (`internal/crypto/testdata/*_vectors.json`), byte-equality, never regenerated.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate envelope-encryption-kms --strict`
