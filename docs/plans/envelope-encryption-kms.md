---
title: Envelope encryption & KMS (per-user DEK / regional KEK)
status: in-progress
design_refs: [§4.4, §7.3, §10]
targets: [internal/crypto/]
promoted_to: null
openspec: changes/envelope-encryption-kms
created: 2026-07-10
---

# Envelope encryption & KMS (plan)

> **Dependency order:** *Foundational — no prerequisites.* This is one of the
> two roots of the build graph (alongside `real-token-issuance`). `user-enrollment`
> depends on it (it needs a DEK to wrap `pairwise_secret`), so build this first.

## Problem

`internal/crypto` is an empty stub (`doc.go` only). Every 🔒 column in the data
model (§10) — `users.dek_wrapped`, `users.pairwise_secret`, `credentials.password_hash`,
`mfa_factors.secret` — presupposes a working envelope-encryption primitive that
does not yet exist. Nothing can write a real encrypted row until it does, and
the **crypto-shred** erasure guarantee (§11.6) is impossible without it. This is
the crypto foundation the enrollment and secret-storage paths sit on.

## Proposed approach

Implement §4.4 envelope encryption in `internal/crypto` as small, pure,
testable pieces behind narrow interfaces:

- **`Encryptor` / `Decryptor`** — AES-256-GCM over a per-user **Data Encryption
  Key (DEK)**. Encrypt takes plaintext + a DEK; returns nonce‖ciphertext‖tag.
  Decrypt fails **closed** (returns an error, never partial plaintext) on any
  tag mismatch.
- **`KeyProvider`** — wraps/unwraps a DEK under a regional **Key Encryption Key
  (KEK)**. Two implementations behind the same interface:
  - `localKeyProvider` (dev/test): KEK derived from an env-supplied secret via
    HKDF; deterministic, hermetic, **never for production**, self-identifying.
  - `kmsKeyProvider` (prod, later): wrap/unwrap calls to the regional KMS/HSM
    so the KEK **never leaves the HSM boundary** (§7.3).
- **`GenerateDEK`** — 256-bit CSPRNG DEK per user.
- **Crypto-shred** — erasure = destroy the wrapped DEK (`users.dek_wrapped`).
  Once gone, every column encrypted under it is unrecoverable, satisfying GDPR
  erasure even against immutable backups (§11.6).

The DEK is only ever held in memory transiently; at rest we store only the
KEK-**wrapped** DEK. Region is threaded through `KeyProvider` so a wrap/unwrap
never crosses a jurisdiction (§5.4).

## DESIGN alignment

Realizes §4.4 (envelope encryption, crypto-shred) and §7.3 (regional KMS/HSM
holds KEKs; asymmetric signing keys are a *separate* concern owned by
`real-token-issuance`). Serves the 🔒 columns in §10. Does **not** change
`DESIGN.md`.

## Target code paths

- `internal/crypto/envelope.go` — `Encryptor`/`Decryptor` (AES-256-GCM), `GenerateDEK`
- `internal/crypto/keyprovider.go` — `KeyProvider` interface + `localKeyProvider`
- `internal/crypto/keyprovider_kms.go` — `kmsKeyProvider` scaffold (prod, deferred)
- `internal/crypto/envelope_test.go`, `internal/crypto/keyprovider_test.go`
- `internal/crypto/testdata/*_vectors.json` — frozen golden vectors (F2 discipline)

## Implementation checklist

- [ ] `Encryptor`/`Decryptor` over AES-256-GCM; nonce is per-message CSPRNG; decrypt fails closed.
- [ ] `GenerateDEK` (256-bit CSPRNG).
- [ ] `KeyProvider` interface: `WrapDEK(ctx, region, dek) ([]byte, error)` / `UnwrapDEK(ctx, region, wrapped) ([]byte, error)`.
- [ ] `localKeyProvider` (HKDF from env secret) — self-identifying, dev-only, refuses to run if the secret is empty.
- [ ] `kmsKeyProvider` scaffold documenting the HSM boundary (implementation deferred).
- [ ] Crypto-shred helper / documented pattern (delete `dek_wrapped`).
- [ ] Frozen golden vectors for GCM round-trips (byte-equality, never regenerated).
- [ ] Tests: round-trip, tamper-detection (fail-closed), wrong-region rejection, wrap/unwrap identity, crypto-shred renders ciphertext unrecoverable.
- [ ] Author & verify paired OpenSpec change: `openspec validate envelope-encryption-kms --strict`
- [ ] Reconcile & promote: `@plan promote envelope-encryption-kms`

## Risks & open questions

- **KEK rotation** for wrapped DEKs (re-wrap on rotate) is out of scope for v1 — document the seam, don't build it yet.
- The dev `localKeyProvider` must be impossible to mistake for prod — refuse empty secrets, log a loud dev-only banner, and gate behind config.
- Golden vectors for GCM must pin the nonce in the test harness (inject the RNG) so round-trip vectors are reproducible without making production nonces deterministic.

## Definition of done

`go build/vet/test ./...` green; AES-256-GCM encrypt/decrypt with fail-closed
tamper detection; `KeyProvider` with a working dev `localKeyProvider` + a
documented `kmsKeyProvider` seam; crypto-shred pattern documented and tested;
frozen vectors byte-match; `make agent-check` clean. Ready to `@plan promote`.
