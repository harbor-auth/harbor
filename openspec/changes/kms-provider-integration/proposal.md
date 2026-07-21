# Proposal: KMS provider integration (real regional KEK)

## Problem

`envelope-encryption-kms` shipped the per-user DEK / regional KEK envelope that
every 🔒 column in the data model (§10) depends on, but the **production** KEK
path is only a scaffold: `kmsKeyProvider` in `internal/crypto/keyprovider_kms.go`
returns `ErrKMSNotImplemented` from both `WrapDEK` and `UnwrapDEK`. This is the
only shipped feature whose own docs flag a scaffold as a known gap, and it
blocks any production deployment that stores real encrypted rows:

- The dev `localKeyProvider` derives the KEK in application memory (HKDF from an
  env secret) and is explicitly **not** production-safe — it violates the §7.3
  guarantee that the KEK never leaves the HSM/KMS boundary.
- There is no way to rotate a regional KEK independently of the DEKs it wraps.

## Proposed Solution

Implement `kmsKeyProvider` behind the **existing** `KeyProvider` interface
(drop-in scaffold replacement — no caller or wiring changes):

1. **Vendor-neutral `kmsClient` seam** — a narrow internal interface
   (`Encrypt(ctx, keyID, plaintext)` / `Decrypt(ctx, keyID, ciphertext)`) that
   every cloud KMS and PKCS#11 HSM can back. `kmsKeyProvider` depends on this
   seam, never on a vendor SDK, keeping the crypto package vendor-neutral and
   hermetically testable.
2. **Region→key-ID resolution** — `WrapDEK`/`UnwrapDEK` map the caller's
   `region` to the regional KEK key-ID via injected config. An **unknown region
   fails closed** (generic error) and NEVER falls back to another region's KEK
   (§5.4 jurisdiction invariant).
3. **Versioned wrapped-DEK envelope** — the wrapped bytes are a self-describing
   envelope (`version`, `region`, `kek_key_id`, ciphertext) so `UnwrapDEK` can
   verify the recorded region/key-ID matches the caller before decrypting; a
   mismatch or parse failure fails closed.
4. **`RewrapDEK` KEK-rotation primitive** — unwrap under the header's KEK,
   re-wrap under the region's current KEK key-ID, without exposing DEK plaintext
   beyond the transient window.
5. **Fail-closed posture preserved** — no method panics; unwrap failures return
   ONE generic error (decryption-oracle defense); a genuinely unconfigured
   provider still returns `ErrKMSNotImplemented`.

## Non-Goals

- Baking any specific vendor SDK (AWS/GCP/Vault/PKCS#11) into the crypto
  package — adapters live behind the `kmsClient` seam.
- Bulk KEK-rotation orchestration (iterate all DEKs in a region) — this change
  ships the `RewrapDEK` primitive, not the batch job.
- Letting KMS mint DEKs (data-key API) — Harbor keeps DEK lifecycle
  (`GenerateDEK`) in-package; KMS only wraps.
- Any change to the `KeyProvider` interface or its callers/wiring.

## Success Criteria

- [ ] Vendor-neutral `kmsClient` seam + in-process fake for hermetic tests.
- [ ] `kmsKeyProvider.WrapDEK` emits a versioned self-describing envelope.
- [ ] `kmsKeyProvider.UnwrapDEK` validates region/key-ID before decrypting; mismatch fails closed.
- [ ] Unknown region fails closed; never falls back to another region's KEK.
- [ ] `RewrapDEK` re-wraps under the current KEK without exposing DEK plaintext.
- [ ] No method panics; unwrap failures return one generic error (no oracle).
- [ ] `KeyProvider` interface + all callers/wiring unchanged.
- [ ] Docker-Compose KMS-emulator integration lane exercises the vendor path.
- [ ] `make agent-check` clean.
