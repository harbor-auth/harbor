package crypto

import "errors"

// Sentinel errors returned by this package.
var (
	// ErrDecryptFailed is returned by Decrypt and UnwrapDEK on any failure:
	// tag mismatch, tampered ciphertext, wrong AAD, wrong region, or short
	// input. A single generic error prevents callers from distinguishing which
	// check failed (decryption-oracle defense).
	ErrDecryptFailed = errors.New("crypto: decryption failed")

	// ErrRandFailure is returned when the system random number generator fails
	// or returns a degenerate (all-zero) value.
	ErrRandFailure = errors.New("crypto: random number generator failure")

	// ErrEmptySecret is returned by NewLocalKeyProvider when the secret is empty.
	ErrEmptySecret = errors.New("crypto: key provider secret must be non-empty")

	// ErrKMSNotImplemented is returned by kmsKeyProvider methods until the
	// regional KMS/HSM integration is implemented.
	ErrKMSNotImplemented = errors.New("crypto: KMS key provider is not yet implemented")
)
