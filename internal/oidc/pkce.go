package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

// ChallengeMethodS256 is the only PKCE method Harbor accepts. `plain` is
// rejected — it provides no protection against a leaked authorization code
// (docs/DESIGN.md §3.1, §11.7).
const ChallengeMethodS256 = "S256"

var (
	// ErrUnsupportedChallengeMethod is returned for any method other than S256.
	ErrUnsupportedChallengeMethod = errors.New("oidc: unsupported code_challenge_method (S256 required)")
	// ErrPKCEMismatch is returned when SHA256(code_verifier) != code_challenge.
	ErrPKCEMismatch = errors.New("oidc: PKCE verification failed")
	// ErrInvalidVerifierLength is returned when a code_verifier is outside the
	// RFC 7636 §4.1 bounds (43–128 characters).
	ErrInvalidVerifierLength = errors.New("oidc: code_verifier length must be 43–128 characters")
)

// verifierMinLen/verifierMaxLen are the RFC 7636 §4.1 code_verifier bounds.
const (
	verifierMinLen = 43
	verifierMaxLen = 128
)

// ValidateVerifier enforces the RFC 7636 §4.1 length bounds on a code_verifier.
// A too-short verifier weakens PKCE; a too-long one is malformed.
func ValidateVerifier(verifier string) error {
	if len(verifier) < verifierMinLen || len(verifier) > verifierMaxLen {
		return ErrInvalidVerifierLength
	}
	return nil
}

// ValidateChallengeMethod accepts only "S256"; everything else (including the
// empty string and "plain") is rejected.
func ValidateChallengeMethod(method string) error {
	if method != ChallengeMethodS256 {
		return ErrUnsupportedChallengeMethod
	}
	return nil
}

// ComputeS256Challenge returns the PKCE `code_challenge` for a verifier:
// base64url(SHA256(verifier)) with no padding (RFC 7636 §4.2).
func ComputeS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyChallenge checks a presented code_verifier against the stored
// code_challenge using a CONSTANT-TIME comparison (so a timing side-channel
// can't leak the challenge). The verifier length is checked first (RFC 7636
// §4.1); the compare returns ErrPKCEMismatch on any difference. At the /token
// layer both failures collapse to invalid_grant, so neither leaks which check
// failed.
func VerifyChallenge(verifier, challenge string) error {
	if err := ValidateVerifier(verifier); err != nil {
		return err
	}
	computed := ComputeS256Challenge(verifier)
	if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
		return ErrPKCEMismatch
	}
	return nil
}
