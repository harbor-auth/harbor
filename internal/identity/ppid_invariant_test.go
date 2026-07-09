package identity_test

// Invariant anchor for the pairwise-secret non-negotiable (registry:
// INV-PPID-PAIRWISE-SECRET). The sub must be keyed by a PER-USER secret (not a
// global salt) and be non-correlating across RP sectors. See docs/DESIGN.md
// §3.2, §A.8.

import (
	"testing"

	"github.com/harbor/harbor/internal/identity"
)

//harbor:invariant INV-PPID-PAIRWISE-SECRET
func TestDerivePPIDDifferentSectorsUnrelated(t *testing.T) {
	secret := []byte("user-1-pairwise-secret-32bytes!!")
	const userID = "user-1"

	subA, err := identity.DerivePPID(secret, "https://rp-a.example", userID)
	if err != nil {
		t.Fatalf("DerivePPID(sector A) error = %v", err)
	}
	subB, err := identity.DerivePPID(secret, "https://rp-b.example", userID)
	if err != nil {
		t.Fatalf("DerivePPID(sector B) error = %v", err)
	}

	// Non-correlating: two RP sectors for the SAME user yield unrelated subs, so
	// RPs cannot join a user across services.
	if subA == subB {
		t.Errorf("different sectors produced the same sub (%q) — subs must not correlate across RPs", subA)
	}

	// Per-user secret: a different pairwise secret (a different user) yields a
	// different sub even for the same sector — there is no single global secret
	// whose compromise deanonymizes everyone.
	otherSecret := []byte("user-2-pairwise-secret-32bytes!!")
	subOther, err := identity.DerivePPID(otherSecret, "https://rp-a.example", userID)
	if err != nil {
		t.Fatalf("DerivePPID(other secret) error = %v", err)
	}
	if subOther == subA {
		t.Errorf("different pairwise secrets produced the same sub — the secret must be per-user, not global")
	}
}
