---
title: HSM / KMS-backed signing key (§7.3)
status: planned
design_refs: [§7.3, §3.5.4, §3.3]
targets: [internal/crypto/, internal/clients/, cmd/harbor-hot/, deploy/helm/]
depends_on: [signing-key-rotation, kms-provider-integration]
wave: 6
priority: P1
created: 2026-07-22
---

# HSM / KMS-backed signing key (plan)

> **Priority:** Wave 6 P1 — long-lead, start early. Tokens are currently signed
> with an ephemeral in-process key that is regenerated on every restart, causing
> all issued tokens to immediately become unverifiable. This is the single
> biggest token-lifecycle gap remaining after the Wave 4/5 landings.

> **Dependencies:** `signing-key-rotation` ✅ (DB schema, rotation state machine,
> `DBSigningKeyStore`, `KeyRotator` all complete) · `kms-provider-integration`
> ✅ (KMS client wiring groundwork done).

---

## Problem

`cmd/harbor-hot/main.go` wires `oidc.NewPlaceholderIssuer()` for JWT issuance.
The underlying `crypto.LocalSigner` generates a **fresh ephemeral P-256 key on
every process start** and holds it purely in memory. Two compounding failures
result:

1. **Restart = total token invalidation.** Every pod restart, rolling deploy,
   or crash regenerates the signing key. All previously issued JWTs — even
   short-lived access tokens still within their `exp` window — immediately fail
   RS/ES256 verification at every RP. Users see silent 401s with no path to
   recovery except re-login.

2. **Key never survives across replicas.** `harbor-hot` runs as 3+ replicas
   (HPA min=3). Each replica has a *different* ephemeral key. A token signed by
   replica A is rejected by replica B — so roughly 2/3 of token verifications
   fail, making the system effectively non-functional under real multi-replica
   load.

3. **`hsmSigner` and `kmsKeyProvider` are scaffolds.** `internal/crypto/signer_hsm.go`
   returns `ErrHSMNotImplemented` for all methods. `internal/crypto/keyprovider_kms.go`
   returns `ErrKMSNotImplemented`. The injection seams exist (`KeyRotator.WithGenerator`,
   `KeyProvider` interface) but nothing connects them to a real KMS.

The rotation infrastructure (`signing_keys` DB table, `DBSigningKeyStore`,
`RotationManager`, `KeyRotator`) is fully built and tested. What is missing is
the production key generator and the KMS client behind `kmsKeyProvider`.

---

## Proposed approach

### Phase 1 — KMS-wrapped key (ships in ~1 week)

The private key is generated in-process, immediately encrypted by AWS KMS, and
stored in `signing_keys.private_key_wrapped`. On startup, Harbor decrypts the
blob via KMS and reconstructs an in-process signer. The KEK never appears in
memory longer than a single KMS API call.

```
startup:
  if KMS_KEY_ARN && DATABASE_URL:
    row = DBSigningKeyStore.GetActive()
    privateKey = KMS.Decrypt(row.private_key_wrapped)
    signer = NewKMSBackedSigner(privateKey, kid)   ← new type in signer_kms.go
  else:
    signer = NewLocalSigner()                      ← dev fallback (unchanged)

rotation (POST /admin/keys/rotate):
  key = ecdsa.GenerateKey(P256)
  wrapped = KMS.Encrypt(key.D.Bytes())
  DBSigningKeyStore.Create({kid, pubKey, privateKeyWrapped: wrapped})
  KeyRotator schedules pending → active → retired lifecycle
```

Security properties:
- Private key encrypted at rest in Postgres with AES-256 (KMS-managed KEK)
- KMS key policy restricts Decrypt to the harbor-hot service account / IAM role
- Decrypted key lives in process memory only; never written to disk or logs
- KMS audit trail (CloudTrail) records every Decrypt call

### Phase 2 — True asymmetric KMS signing (~2 weeks, post-Phase-1)

Key is generated **inside KMS** as an `ECC_NIST_P256` asymmetric key. `Sign()`
calls `kms:Sign`; private key material never leaves the KMS HSM boundary. This
is the design intent of `hsmSigner` (DESIGN.md §7.3).

```
Sign(digest):
  resp = kms.Sign(KeyId: KMS_KEY_ARN, Message: digest, SigningAlgorithm: ECDSA_SHA_256)
  return derToRaw(resp.Signature)   ← convert DER → R‖S (RFC 7518 §3.4)
```

Phase 2 is implemented as `hsmSigner` (currently the scaffold file). Phase 1
uses a new `KMSBackedSigner` in `signer_kms.go` that bridges the gap.

---

## Target code paths

| File | Change |
|------|--------|
| `internal/crypto/signer_kms.go` | New: `KMSBackedSigner` wrapping decrypted in-process key; constructor takes `*ecdsa.PrivateKey` + kid + log source |
| `internal/crypto/keyprovider_kms.go` | Implement `WrapDEK`/`UnwrapDEK` via `github.com/aws/aws-sdk-go-v2/service/kms` |
| `internal/crypto/kms_client.go` | New: `NewKMSClient(keyARN, region, endpoint)` factory; returns `*kms.Client` |
| `cmd/harbor-hot/main.go` | Bootstrap: if `KMS_KEY_ARN` + `DATABASE_URL` → load active key from DB, decrypt, build `KMSBackedSigner`; wire into `KeyRotator.WithGenerator` |
| `internal/clients/signingkeys_rotstore.go` | New: `DBRotationStore` adapter implementing `crypto.RotationStore` over `DBSigningKeyStore` |
| `deploy/helm/values.yaml` | Add `hot.kms.keyArn`, `hot.kms.region`, `hot.kms.endpoint` |
| `deploy/helm/templates/configmap-hot.yaml` | Expose `KMS_KEY_ARN`, `KMS_REGION`, `KMS_ENDPOINT` env vars |
| `internal/crypto/signer_hsm.go` | Phase 2: implement `hsmSigner` as true KMS asymmetric signer |

---

## Implementation checklist

### Phase 1 — KMS-wrapped key

- [ ] Add `github.com/aws/aws-sdk-go-v2/service/kms` to `go.mod` (check if
      already present from `kms-provider-integration`)
- [ ] `internal/crypto/kms_client.go` — `NewKMSClient(keyARN, region, endpoint string)` returns
      `*kms.Client`; `endpoint` is for LocalStack in CI
- [ ] `internal/crypto/keyprovider_kms.go` — implement `WrapDEK`/`UnwrapDEK`
      using `kms.Encrypt` / `kms.Decrypt` (DataKeySpec: `AES_256`);
      replace scaffold `ErrKMSNotImplemented` returns
- [ ] `internal/crypto/signer_kms.go` — `KMSBackedSigner` struct:
      holds `*ecdsa.PrivateKey` + kid + `JWK`; implements `Signer`;
      logs `"kms-backed signer"` at construction (not DEV-ONLY warning)
- [ ] `internal/clients/signingkeys_rotstore.go` — `DBRotationStore` implementing
      `crypto.RotationStore` (Create, ActiveKid, Promote, Retire) over `DBSigningKeyStore`;
      handles `PrivateKeyWrapped` passthrough so `KeyRotator` can store the KMS blob
- [ ] `cmd/harbor-hot/main.go` — `buildSigner(ctx, logger, pool, kmsClient)`:
      - If `DATABASE_URL` unset OR `KMS_KEY_ARN` unset → fall back to `NewLocalSigner()`
      - Else: call `DBSigningKeyStore.GetActive(ctx)`; if `ErrSigningKeyNotFound` →
        first-run: generate key, wrap with KMS, call `DBSigningKeyStore.Create()`
      - Decrypt `row.PrivateKeyWrapped` via KMS; reconstruct `*ecdsa.PrivateKey`;
        return `NewKMSBackedSigner(priv, kid)`
- [ ] Wire `KeyRotator.WithGenerator` with a KMS-aware generator
      (generates P-256 key, wraps with KMS, returns `KMSBackedSigner`)
- [ ] Helm: `values.yaml` → `hot.kms.{keyArn,region,endpoint}`;
      `configmap-hot.yaml` → env vars `KMS_KEY_ARN`, `KMS_REGION`, `KMS_ENDPOINT`
- [ ] Unit tests (mock KMS client): `TestKMSBackedSigner_Sign`,
      `TestKMSKeyProvider_WrapUnwrap`, `TestBuildSigner_LocalFallback`,
      `TestBuildSigner_KMSPath`
- [ ] Integration test with LocalStack (tagged `//go:build integration`):
      full rotation: generate → wrap → store → decrypt → sign → verify
- [ ] `go vet ./...` + `make agent-check` green

### Phase 2 — True asymmetric KMS signing (deferred)

- [ ] `internal/crypto/signer_hsm.go` — implement `hsmSigner`:
      `Sign()` calls `kms.Sign(ECDSA_SHA_256)`; `PublicJWK()` calls `kms.GetPublicKey()`
      and parses the DER-encoded P-256 pubkey; `KeyID()` derives kid from pubkey bytes
- [ ] `internal/crypto/kms_client.go` — add `SignDigest(ctx, keyID, digest)` and
      `GetPublicKey(ctx, keyID)` helpers
- [ ] Update `buildSigner` in `main.go` to prefer `hsmSigner` when
      `KMS_ASYMMETRIC=true` (or auto-detect from key type via `DescribeKey`)
- [ ] Tests: DER→raw-ES256 conversion; public key parse round-trip; sign+verify

---

## DESIGN alignment

- **§7.3** (signing key lifecycle, HSM seam): Phase 1 fills the KMS-wrapped
  intermediate; Phase 2 completes the true HSM boundary.
- **§3.5.4** (emergency kid rotation): already fully wired by `signing-key-rotation`
  ✅; this feature ensures the key being rotated is KMS-protected.
- **§6.5** (no key material in logs): `KMSBackedSigner` logs `"kms-backed signer"` +
  kid only; private key bytes and KMS plaintext never appear in structured logs.
- **§5** (regional data sovereignty): `KMS_KEY_ARN` is region-specific;
  `kmsKeyProvider.WrapDEK` passes `region` as AAD so blobs can't cross regions.

---

## Risks & mitigations

| Risk | Mitigation |
|------|-----------|
| KMS latency on startup (Decrypt call) | Single call at boot only; cached in-process for lifetime of pod |
| LocalStack not available in CI | Integration tests tagged `//go:build integration`; unit tests use mock client |
| `go.mod` already has AWS SDK v2 from `kms-provider-integration` | Check before adding; avoid duplicate dependency |
| First-run with no active key in DB | `buildSigner` handles this: generates and persists a new key automatically |
| Phase 2 DER→R‖S conversion bugs | Covered by existing `signer_test.go` patterns; add new golden vector test |
| KMS key ARN not set in dev | Dev falls back to `LocalSigner` (unchanged behaviour); loud log warning |

---

## Definition of done

`go build/vet/test ./...` green; `make agent-check` clean; with `KMS_KEY_ARN`
+ `DATABASE_URL` set, `harbor-hot` starts, loads (or generates) an active
signing key from DB, issues tokens that survive a pod restart, and passes e2e
`flow_test.go`; without `KMS_KEY_ARN`, dev path falls back to `LocalSigner`
with a DEV-ONLY warning (no regression); unit tests cover both paths;
Helm chart exposes the three KMS env vars.
