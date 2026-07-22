# Proposal: Envelope encryption & KMS (per-user DEK / regional KEK)

## Problem

`internal/crypto` is an empty stub. Every 🔒 column in the data model (DESIGN
§10) — `users.dek_wrapped`, `users.pairwise_secret`, `credentials.password_hash`,
`mfa_factors.secret` — presupposes a working envelope-encryption primitive that
does not exist. No real encrypted row can be written, and the crypto-shred
erasure guarantee (§11.6) is impossible.

## Proposed Solution

Implement DESIGN §4.4 envelope encryption in `internal/crypto`:

- `Encryptor`/`Decryptor` over **AES-256-GCM** keyed by a per-user **DEK**;
  decrypt fails **closed** on any tag mismatch.
- `KeyProvider` that wraps/unwraps a DEK under a regional **KEK**; a dev
  `localKeyProvider` (HKDF from an env secret) and a deferred `kmsKeyProvider`
  seam where the KEK never leaves the HSM boundary (§7.3).
- `GenerateDEK` (256-bit CSPRNG) and a crypto-shred pattern (destroy
  `dek_wrapped` ⇒ data unrecoverable).

## Non-Goals

- KEK rotation / DEK re-wrapping (seam only).
- The production KMS/HSM integration (`kmsKeyProvider` is a documented scaffold).
- Token *signing* keys — those are owned by `real-token-issuance`.

## Success Criteria

- [ ] AES-256-GCM encrypt/decrypt round-trips; tampered ciphertext is rejected (fail-closed).
- [ ] `GenerateDEK` produces a 256-bit key; `KeyProvider` wrap→unwrap is identity.
- [ ] A wrap/unwrap under the wrong region is rejected.
- [ ] Crypto-shred renders previously-encrypted data unrecoverable (test-proven).
- [ ] Frozen golden vectors byte-match; `make agent-check` clean.
