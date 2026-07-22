---
change: hsm-signing-key
kind: proposal
status: draft
created: 2026-07-22
---

# Proposal: HSM / KMS-backed signing key

## Problem

Harbor currently signs JWTs with a `LocalSigner` that generates a fresh
ephemeral P-256 key on every process start. This makes the system completely
non-functional for production use:

- **Pod restart = all tokens invalidated.** Any rolling deploy or crash
  regenerates the signing key; every RP immediately rejects all outstanding
  JWTs (wrong `kid`).
- **Multi-replica incoherence.** With HPA min=3, each replica holds a different
  ephemeral key. A token signed by replica A is rejected by replica B. ~66% of
  verifications fail under normal load.
- **`hsmSigner` and `kmsKeyProvider` are stubs.** The scaffolds exist and
  the injection seams are wired (`KeyRotator.WithGenerator`), but nothing
  connects them to a real key-protection service.

## Motivation

The `signing-key-rotation` feature (✅ merged) built the full rotation
infrastructure: `signing_keys` DB table, `DBSigningKeyStore`, `RotationManager`,
`KeyRotator`. The only missing piece is a production key generator that stores
key material durably and protects it at rest.

AWS KMS (already used by `kms-provider-integration` for DEK wrapping) is the
natural choice for Harbor's AWS-hosted deployment target. It provides:
- AES-256 envelope encryption at rest (KMS-managed KEK)
- IAM-gated Decrypt access (service account scoped)
- CloudTrail audit of every key operation

## User-visible changes

None to end users. This is an internal key-security improvement. Externally:
- JWKS endpoint continues to return the same ES256 key structure
- Token `kid` claim continues to work as before
- After the fix: tokens survive pod restarts and are consistent across replicas

## Operator-visible changes

New environment variables for `harbor-hot`:

| Variable | Required in prod | Description |
|---|---|---|
| `KMS_KEY_ARN` | Yes | ARN of the AWS KMS symmetric key used to wrap the signing private key |
| `KMS_REGION` | Yes (if not from EC2 metadata) | AWS region of the KMS key |
| `KMS_ENDPOINT` | No (LocalStack only) | Custom KMS endpoint URL for local testing |

When `KMS_KEY_ARN` is unset, `harbor-hot` falls back to the ephemeral
`LocalSigner` (dev behaviour unchanged).

## API changes

No OpenAPI surface changes. `POST /admin/keys/rotate` (already shipped in
`signing-key-rotation`) operates identically; in production it now generates a
KMS-wrapped key instead of an ephemeral one.

## Phases

- **Phase 1 (this PR):** KMS-wrapped key — private key generated in-process,
  encrypted by KMS, stored in `signing_keys.private_key_wrapped`.
- **Phase 2 (follow-on):** True asymmetric KMS signing — key generated inside
  KMS, `Sign()` calls `kms:Sign`, private key never leaves KMS HSM.
