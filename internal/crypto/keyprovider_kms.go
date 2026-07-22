package crypto

import "context"

// kmsKeyProvider is the production KeyProvider. It wraps/unwraps DEKs using
// a regional KMS or HSM so the KEK never leaves the HSM boundary
// (docs/DESIGN.md §7.3).
//
// This is a scaffold: the interface contract is complete so callers and wiring
// can reference it, but the KMS/HSM implementation is deferred. All methods
// return [ErrKMSNotImplemented] rather than panicking, so a misconfigured
// deployment fails closed and gracefully instead of crashing the process.
type kmsKeyProvider struct{}

// WrapDEK is not yet implemented — returns [ErrKMSNotImplemented].
func (k *kmsKeyProvider) WrapDEK(_ context.Context, _ string, _ DEK) ([]byte, error) {
	return nil, ErrKMSNotImplemented
}

// UnwrapDEK is not yet implemented — returns [ErrKMSNotImplemented].
func (k *kmsKeyProvider) UnwrapDEK(_ context.Context, _ string, _ []byte) (DEK, error) {
	return DEK{}, ErrKMSNotImplemented
}
