// Package crypto implements Harbor's envelope encryption and key management
// (docs/DESIGN.md §4.4, §7.3): per-user Data Encryption Keys (DEKs) wrapped
// by a regional Key Encryption Key (KEK), plus the crypto-shred erasure pattern
// for GDPR compliance (§11.6).
//
// The exported primitives are:
//
//   - [Encryptor] / [Decryptor] — AES-256-GCM under a per-user DEK.
//   - [KeyProvider] — wraps/unwraps a DEK under a regional KEK.
//   - [GenerateDEK] — generates a fresh 256-bit DEK from crypto/rand.
//
// Obtain a cipher via [NewCipher] and a dev-only key provider via
// [NewLocalKeyProvider]. The production KeyProvider (kmsKeyProvider) is a
// scaffold whose methods return [ErrKMSNotImplemented].
package crypto
