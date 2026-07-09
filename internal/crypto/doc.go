// Package crypto will implement Harbor's envelope encryption and key management
// (docs/DESIGN.md §4.2, §4.4): per-user Data Encryption Keys (DEKs) wrapped by a
// regional Key Encryption Key (KEK) in KMS/HSM, token signing, and crypto-shred
// on erasure. It is intentionally empty for now: the scaffold documents the
// intended package boundary; implementation lands with the crypto envelope.
package crypto
