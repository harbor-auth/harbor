---
title: KMS provider integration (real regional KEK — replace the fail-closed scaffold)
status: draft
design_refs: [§4.4, §7.3, §A.4]
targets: [internal/crypto/]
promoted_to: null
openspec: changes/kms-provider-integration
created: 2026-07-21
---

# KMS provider integration (plan)

> **Dependency order:** no hard prerequisites. `envelope-encryption-kms` has
> shipped the `KeyProvider` seam (`WrapDEK`/`UnwrapDEK`), the dev
> `localKeyProvider`, and the `kmsKeyProvider` **scaffold** that this plan
> replaces. Self-contained in `internal/crypto/` — no hot-path contention, no
> migrations, no other plan touches these files. A **root** of the Wave-4 DAG,
> buildable immediately and in parallel.

## Problem

`envelope-encryption-kms` is shipped and every 🔒 column in the data model (§10)
— `users.dek_wrapped`, `users.pairwise_secret`, `credentials.password_hash`,
`mfa_factors.secret` — depends on its per-user DEK / regional KEK envelope.
But the **production** KEK path is only a scaffold: `kmsKeyProvider` in
`internal/crypto/keyprovider_kms.go` returns `ErrKMSNotImplemented` from both
`WrapDEK` and `UnwrapDEK`. This is the **only shipped feature whose own docs
flag a scaffold as a known gap**, and it is a hard blocker on any production
deployment that stores real encrypted rows: the dev `localKeyProvider` (HKDF
from an env secret) is explicitly **not** production-safe, because the KEK it
derives lives in application memory rather than behind an HSM boundary (§7.3).

Without a real KMS provider, Harbor cannot honour its data-sovereignty promise
that **the KEK never leaves the regional HSM boundary** (§7.3, §A.4) and cannot
rotate a regional KEK independently of the DEKs it wraps.

## Proposed approach

Implement `kmsKeyProvider` as a **real regional KEK provider** behind the
existing `KeyProvider` interface, so no caller or wiring changes — only the
scaffold body is filled in.

1. **KMS client seam** — introduce a narrow internal interface (e.g.
   `kmsClient`) with `Encrypt(ctx, keyID, plaintext) ([]byte, error)` /
   `Decrypt(ctx, keyID, ciphertext) ([]byte, error)`, modelling the
   envelope-wrap primitive every cloud KMS (AWS KMS, GCP KMS, Vault Transit)
   and PKCS#11 HSM exposes. `kmsKeyProvider` depends on this seam, not on any
   one vendor SDK — keeping the crypto package vendor-neutral and testable.
2. **Region → key-ID resolution** — `WrapDEK(ctx, region, dek)` and
   `UnwrapDEK(ctx, region, wrapped)` resolve the caller's `region` to the
   **regional KEK key-ID** via an injected `map[string]string` (region → KMS
   key ARN/URI). An unknown region MUST fail closed (generic error), never
   silently fall back to another region's key — the invariant that a
   wrap/unwrap never crosses a jurisdiction (§5.4).
3. **Wrapped-DEK envelope format** — the wrapped bytes are a self-describing
   envelope: a small versioned header (`version`, `region`, `kek_key_id`)
   prepended to the KMS ciphertext, so `UnwrapDEK` can validate the region /
   key-ID recorded at wrap time matches the caller's region before asking the
   KMS to decrypt. A header/region mismatch fails closed.
4. **KEK rotation seam** — add a `RewrapDEK(ctx, region, wrapped) ([]byte,
   error)` operation that unwraps under the KEK recorded in the envelope header
   and re-wraps under the region's **current** KEK key-ID, enabling a KEK
   rotation to re-wrap existing DEKs without ever exposing DEK plaintext beyond
   the transient in-memory window. (Bulk re-wrap orchestration is out of scope
   — this plan provides the primitive, not the batch job.)
5. **Emulator-backed tests** — tests run against an in-process fake `kmsClient`
   (deterministic wrap = header ‖ nonce ‖ AEAD-under-test-KEK) so the full
   `WrapDEK`→`UnwrapDEK`→`RewrapDEK` path is covered hermetically, with a
   Docker-Compose integration lane wiring a real KMS emulator (e.g.
   LocalStack KMS) for the vendor-adapter path.

**Alternatives considered.** *Bake a vendor SDK (AWS KMS) directly into
`kmsKeyProvider`* — rejected: couples the crypto package to one cloud, makes
hermetic testing impossible, and violates the vendor-neutral seam the design
assumes (§A.4). *Store the KEK in a mounted secret and wrap in-process* —
rejected: that is exactly what `localKeyProvider` already does, and it defeats
the §7.3 guarantee that the KEK never leaves the HSM boundary. *Data-key-only
API (let KMS mint DEKs)* — rejected: Harbor already owns DEK generation
(`GenerateDEK`, with RNG-integrity checks); we only want KMS to *wrap*, keeping
DEK lifecycle inside `internal/crypto`.

## DESIGN alignment

Realises §4.4 (envelope encryption: per-user DEK wrapped under a regional KEK),
§7.3 (the KEK never leaves the HSM/KMS boundary), and Appendix §A.4 (KMS &
key-management threat model). It does **not** change `DESIGN.md` — §4.4 and §7.3
already specify a KMS-backed KEK; this plan finally *implements* the provider
the design has always assumed. The vendor-neutral `kmsClient` seam is an
implementation detail, not a design change.

## Target code paths

- `internal/crypto/keyprovider_kms.go` — replace the scaffold body with the
  real `kmsKeyProvider` (region→key-ID resolution, versioned wrapped-DEK
  envelope, fail-closed unknown-region handling).
- `internal/crypto/kmsclient.go` — new narrow `kmsClient` seam + a fake
  implementation for tests (vendor adapters live behind this interface).
- `internal/crypto/keyprovider_kms_test.go` — emulator/fake-backed round-trip,
  wrong-region, rotation, and fail-closed tests.
- `internal/crypto/errors.go` — retain `ErrKMSNotImplemented` only for genuinely
  unconfigured deployments; add fail-closed sentinels as needed (still generic
  to callers).

## Implementation checklist

- [ ] Define the narrow `kmsClient` seam (`Encrypt`/`Decrypt` by key-ID) in `internal/crypto/kmsclient.go`; provide an in-process **fake** for hermetic tests.
- [ ] Implement `kmsKeyProvider.WrapDEK`: resolve `region` → KEK key-ID; call `kmsClient.Encrypt`; emit a versioned self-describing envelope (`version`, `region`, `kek_key_id`, ciphertext).
- [ ] Implement `kmsKeyProvider.UnwrapDEK`: parse+validate the envelope header (region + key-ID must match the caller's `region`); call `kmsClient.Decrypt`; return `DEK`. Any mismatch/parse failure returns the generic fail-closed error (no oracle signal).
- [ ] Implement `RewrapDEK` (KEK-rotation primitive): unwrap under the header's KEK, re-wrap under the region's current KEK key-ID; DEK plaintext never leaves the transient window.
- [ ] Region→key-ID resolution: unknown region fails closed (generic error), NEVER falls back to another region's KEK (§5.4 jurisdiction invariant).
- [ ] Preserve the fail-closed posture: no method panics; a misconfigured/unconfigured provider returns a generic error (keep `ErrKMSNotImplemented` for the genuinely-unconfigured case).
- [ ] Keep the `KeyProvider` interface + all existing callers/wiring unchanged (drop-in scaffold replacement).
- [ ] Tests: `WrapDEK`→`UnwrapDEK` round-trip (fake KMS); wrong-region unwrap rejected (fail closed); tampered envelope header rejected; `RewrapDEK` produces a DEK-preserving re-wrap; unknown-region wrap/unwrap fails closed; no panic on any bad input.
- [ ] Tests (integration lane): Docker-Compose KMS emulator (e.g. LocalStack) exercises the real vendor-adapter `kmsClient` path.
- [ ] Update `docs/features/envelope-encryption-kms.md` "Known gaps" on promotion (scaffold → implemented).
- [ ] Author & verify paired OpenSpec change: `openspec validate kms-provider-integration --strict`
- [ ] Reconcile & promote: `@plan promote kms-provider-integration`

## Risks & open questions

- **Vendor coupling** — the `kmsClient` seam must stay vendor-neutral; the AWS/
  GCP/Vault/PKCS#11 adapter lives *behind* the interface, never in
  `kmsKeyProvider` directly. A leak of vendor types into the crypto package is
  a review-blocking regression.
- **Envelope format stability** — the versioned wrapped-DEK header becomes a
  persisted on-disk format (`users.dek_wrapped`). It must be forward/backward
  compatible and versioned from day one; a format change later requires a
  re-wrap migration.
- **Fail-closed vs. fail-open** — unlike the rate limiter, KMS is on the
  **cold/enrolment path**, so it fails **closed** (a KMS outage must not silently
  produce unencrypted or wrongly-wrapped rows). Document the availability
  coupling: enrolment/decrypt operations depend on regional KMS availability.
- **KEK rotation orchestration** — this plan ships the `RewrapDEK` *primitive*;
  the batch re-wrap job (iterate all DEKs in a region on KEK rotation) is a
  follow-up, noted as out of scope.
- **Decryption-oracle discipline** — as with the existing envelope code, every
  unwrap failure returns ONE generic error; the KMS integration must not leak
  which check (region, header, KMS decrypt) failed.

## Definition of done

`go build/vet/test ./internal/crypto/...` green; `kmsKeyProvider` implements a
real region-scoped KEK wrap/unwrap behind the vendor-neutral `kmsClient` seam;
unknown/mismatched regions fail closed without crossing a jurisdiction;
`RewrapDEK` supports KEK rotation without exposing DEK plaintext; a KMS-emulator
integration lane exercises the vendor path; no method panics on bad input;
`docs/features/envelope-encryption-kms.md` "Known gaps" no longer flags the
scaffold; `make agent-check` clean. Ready to `@plan promote`.
