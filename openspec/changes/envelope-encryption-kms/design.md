# Design: Envelope encryption & KMS

## Key Decisions

### Decision 1: AES-256-GCM for the DEK layer
**Chosen:** AES-256-GCM (AEAD), layout `nonce ‖ ciphertext ‖ tag`.
**Rationale:** Authenticated encryption gives tamper-detection for free and lets
decrypt fail closed, matching Harbor's security-first posture (§7). Widely
audited, hardware-accelerated.
**Alternatives considered:** ChaCha20-Poly1305 (fine, but AES-GCM has broader
HSM/KMS support for the KEK side); CBC+HMAC (more footguns, rejected).

### Decision 2: `KeyProvider` interface with dev + HSM implementations
**Chosen:** One `KeyProvider` interface; `localKeyProvider` (HKDF from env
secret) for dev/test, `kmsKeyProvider` seam for prod.
**Rationale:** The wrap/unwrap boundary is exactly where the KEK must stay
inside the HSM (§7.3). An interface lets hermetic tests run without a real KMS
while keeping the production path identical in shape.
**Alternatives considered:** Hard-coding a KMS SDK (breaks hermetic tests, F3);
no abstraction (couples enrollment to a specific KMS, rejected).

### Decision 3: Crypto-shred = destroy the wrapped DEK
**Chosen:** Erasure deletes `users.dek_wrapped`; nothing re-derivable.
**Rationale:** Satisfies GDPR erasure (§11.6) even against immutable backups —
the ciphertext columns become undecryptable the instant the wrapped DEK is gone.
**Alternatives considered:** Row deletion only (backups still hold ciphertext +
recoverable key, rejected).

### Decision 4: Region threaded through wrap/unwrap
**Chosen:** `WrapDEK`/`UnwrapDEK` take `region`; a cross-region unwrap fails.
**Rationale:** Enforces §5.4 data-sovereignty at the crypto boundary, not just
by convention.
**Alternatives considered:** Region as ambient/global config (allows silent
cross-jurisdiction unwrap, rejected).

### Decision 5: Frozen golden vectors with injected RNG
**Chosen:** Test harness injects a fixed nonce/RNG to freeze round-trip vectors;
production always uses `crypto/rand`.
**Rationale:** Byte-equality vectors (F2) catch silent crypto drift without
making real nonces deterministic.
