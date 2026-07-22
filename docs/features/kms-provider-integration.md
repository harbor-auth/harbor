# kms-provider-integration

**Status:** planned  
**DESIGN §:** §3.3, §7.3  
**Code:** `internal/crypto/keyprovider_kms.go` (planned)

KMS-backed signing key provider: sources JWT signing keys from an external KMS
(envelope-encrypted, never exported in plaintext) so rotation and custody are
managed by the cloud/HSM boundary rather than the application process.
