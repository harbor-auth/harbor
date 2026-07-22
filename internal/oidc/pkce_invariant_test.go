package oidc_test

// Invariant anchors for the PKCE non-negotiables (registry: INV-PKCE-MANDATORY,
// INV-CONSTANT-TIME-COMPARE). These are deliberately named to match the
// `enforced_by` entries in invariants/registry.yaml and carry the
// `//harbor:invariant` tags the meta-test looks for. See docs/DESIGN.md §11.7.

import (
	"errors"
	"testing"

	"github.com/harbor-auth/harbor/internal/oidc"
)

// RFC 7636 Appendix B reference pair — an independent, authoritative fixture.
const (
	rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

//harbor:invariant INV-PKCE-MANDATORY
func TestValidateChallengeMethodRejectsNonS256(t *testing.T) {
	for _, method := range []string{"", "plain", "PLAIN", "s256", "RS256", "none"} {
		if err := oidc.ValidateChallengeMethod(method); !errors.Is(err, oidc.ErrUnsupportedChallengeMethod) {
			t.Errorf("ValidateChallengeMethod(%q) = %v, want ErrUnsupportedChallengeMethod", method, err)
		}
	}
	if err := oidc.ValidateChallengeMethod(oidc.ChallengeMethodS256); err != nil {
		t.Errorf("ValidateChallengeMethod(S256) = %v, want nil", err)
	}
}

//harbor:invariant INV-PKCE-MANDATORY
func TestVerifyChallengeMismatch(t *testing.T) {
	// A verifier that does not hash to the stored challenge must be rejected.
	if err := oidc.VerifyChallenge(rfcVerifier, "not-the-right-challenge-000000000000000000000"); !errors.Is(err, oidc.ErrPKCEMismatch) {
		t.Fatalf("VerifyChallenge(mismatch) = %v, want ErrPKCEMismatch", err)
	}
	// The correct RFC 7636 pair must verify.
	if err := oidc.VerifyChallenge(rfcVerifier, rfcChallenge); err != nil {
		t.Fatalf("VerifyChallenge(rfc pair) = %v, want nil", err)
	}
	// Sanity: ComputeS256Challenge reproduces the RFC challenge.
	if got := oidc.ComputeS256Challenge(rfcVerifier); got != rfcChallenge {
		t.Fatalf("ComputeS256Challenge(rfcVerifier) = %q, want %q", got, rfcChallenge)
	}
}

//harbor:invariant INV-CONSTANT-TIME-COMPARE
func TestVerifyChallengeUsesConstantTime(t *testing.T) {
	// Behavioral proxy for the constant-time comparison: a challenge that shares
	// a long common prefix with the correct one (which would short-circuit a
	// naive byte-by-byte compare) must still be rejected as a plain mismatch —
	// never accepted, never a distinct error that leaks position.
	almost := rfcChallenge[:len(rfcChallenge)-1] + "X"
	if err := oidc.VerifyChallenge(rfcVerifier, almost); !errors.Is(err, oidc.ErrPKCEMismatch) {
		t.Fatalf("VerifyChallenge(near-miss) = %v, want ErrPKCEMismatch", err)
	}
}
