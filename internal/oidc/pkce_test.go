package oidc

import (
	"strings"
	"testing"
)

// RFC 7636 Appendix B known-answer vector: a fixed verifier maps to a fixed
// S256 challenge. Pinning this locks the PKCE derivation against silent change.
const (
	rfc7636Verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfc7636Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestComputeS256Challenge_KnownAnswer(t *testing.T) {
	if got := ComputeS256Challenge(rfc7636Verifier); got != rfc7636Challenge {
		t.Fatalf("ComputeS256Challenge = %q, want RFC 7636 vector %q", got, rfc7636Challenge)
	}
}

func TestVerifyChallenge_Success(t *testing.T) {
	if err := VerifyChallenge(rfc7636Verifier, rfc7636Challenge); err != nil {
		t.Fatalf("VerifyChallenge(valid) = %v, want nil", err)
	}
}

func TestVerifyChallenge_Mismatch(t *testing.T) {
	// A well-formed (43-char) but wrong verifier must fail the compare, not the
	// length guard.
	wrong := "WRONGftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"[:43]
	if err := VerifyChallenge(wrong, rfc7636Challenge); err != ErrPKCEMismatch {
		t.Fatalf("VerifyChallenge(mismatch) = %v, want ErrPKCEMismatch", err)
	}
}

// The RFC 7636 §4.1 length guard rejects verifiers outside 43–128 chars before
// the compare runs.
func TestVerifyChallenge_InvalidLength(t *testing.T) {
	for _, v := range []string{"", "too-short", strings.Repeat("a", 42), strings.Repeat("a", 129)} {
		if err := VerifyChallenge(v, rfc7636Challenge); err != ErrInvalidVerifierLength {
			t.Fatalf("VerifyChallenge(len %d) = %v, want ErrInvalidVerifierLength", len(v), err)
		}
	}
	// Boundary lengths (43 and 128) pass the length guard (then fail the compare).
	for _, v := range []string{strings.Repeat("a", 43), strings.Repeat("a", 128)} {
		if err := VerifyChallenge(v, rfc7636Challenge); err != ErrPKCEMismatch {
			t.Fatalf("VerifyChallenge(len %d) = %v, want ErrPKCEMismatch", len(v), err)
		}
	}
}

func TestValidateChallengeMethod(t *testing.T) {
	if err := ValidateChallengeMethod("S256"); err != nil {
		t.Fatalf("S256 = %v, want nil", err)
	}
	for _, m := range []string{"plain", "", "s256", "PLAIN", "S384"} {
		if err := ValidateChallengeMethod(m); err != ErrUnsupportedChallengeMethod {
			t.Fatalf("ValidateChallengeMethod(%q) = %v, want ErrUnsupportedChallengeMethod", m, err)
		}
	}
}
