package crypto

import "errors"

// ErrHSMNotImplemented is returned by hsmSigner methods until the regional HSM
// signing integration is wired (docs/DESIGN.md §7.3).
var ErrHSMNotImplemented = errors.New("crypto: HSM signer is not yet implemented")

// hsmSigner is a SCAFFOLD for the production Signer backed by the regional HSM.
// The private key never leaves the HSM boundary; Sign will send the SHA-256
// digest to the HSM and receive the raw R‖S signature back, converting the
// HSM's DER output as needed.
//
// NOT YET IMPLEMENTED — every method returns ErrHSMNotImplemented (fail-closed,
// never a panic).
type hsmSigner struct{}

// Compile-time proof that hsmSigner implements Signer.
var _ Signer = hsmSigner{}

func (hsmSigner) Sign(_ []byte) ([]byte, error) { return nil, ErrHSMNotImplemented }
func (hsmSigner) KeyID() string                 { return "" }
func (hsmSigner) PublicJWK() JWK                { return JWK{} }
