// Package crypto implements Harbor's envelope encryption and key management
// (docs/DESIGN.md §4.4, §7.3): per-user Data Encryption Keys (DEKs) wrapped
// by a regional Key Encryption Key (KEK), plus the crypto-shred erasure pattern
// for GDPR compliance (§11.6).
//
// # Exported Primitives
//
//   - [Encryptor] / [Decryptor] — AES-256-GCM under a per-user DEK.
//   - [KeyProvider] — wraps/unwraps a DEK under a regional KEK.
//   - [GenerateDEK] — generates a fresh 256-bit DEK from crypto/rand.
//
// Obtain a cipher via [NewCipher] and a dev-only key provider via
// [NewLocalKeyProvider]. The production KeyProvider (kmsKeyProvider) is a
// scaffold whose methods return [ErrKMSNotImplemented].
//
// # Crypto-Shred Erasure Pattern
//
// Harbor implements crypto-shred for GDPR-compliant data erasure (§11.6):
// each user's sensitive data (pairwise_secret, credentials, MFA factors) is
// encrypted under their unique DEK. The DEK itself is stored wrapped by the
// regional KEK in the users.dek_wrapped column.
//
// To permanently erase a user's data:
//
//	DELETE FROM users WHERE user_id = $1;  -- or: UPDATE users SET dek_wrapped = NULL
//
// Once dek_wrapped is deleted, the plaintext DEK is unrecoverable — even by
// Harbor operators with full database access. All columns encrypted under that
// DEK (users.pairwise_secret, credentials.password_hash, mfa_factors.secret)
// become permanently unreadable, satisfying GDPR Article 17 "right to erasure"
// even against immutable backups or database snapshots.
//
// This pattern works because:
//   - The DEK is held in memory only transiently during request processing.
//   - At rest, only the KEK-wrapped form exists (users.dek_wrapped).
//   - The KEK lives exclusively in the regional KMS/HSM boundary.
//   - Without dek_wrapped, there is no path to recover the DEK or decrypt data.
package crypto
