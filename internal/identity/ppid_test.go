package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func mustDerive(t *testing.T, secret []byte, sector, userID string) string {
	t.Helper()
	sub, err := DerivePPID(secret, sector, userID)
	if err != nil {
		t.Fatalf("DerivePPID(%q, %q, %q) unexpected error: %v", secret, sector, userID, err)
	}
	return sub
}

func TestDerivePPID_Deterministic(t *testing.T) {
	secret := []byte("user-pairwise-secret-0000000000000000")
	a := mustDerive(t, secret, "rp.example.com", "user-123")
	b := mustDerive(t, secret, "rp.example.com", "user-123")
	if a != b {
		t.Fatalf("expected deterministic output, got %q and %q", a, b)
	}
}

func TestDerivePPID_EncodingShape(t *testing.T) {
	secret := []byte("user-pairwise-secret-0000000000000000")
	sub := mustDerive(t, secret, "rp.example.com", "user-123")

	// HMAC-SHA256 is 256 bits -> 32 bytes -> RawURLEncoding is 43 chars, unpadded.
	if len(sub) != 43 {
		t.Fatalf("ppid length = %d, want 43", len(sub))
	}
	if _, err := base64.RawURLEncoding.DecodeString(sub); err != nil {
		t.Fatalf("ppid is not valid RawURLEncoding: %v", err)
	}
}

// Golden known-answer vector: this test LOCKS the exact PPID derivation so it
// can never silently regress (docs/DESIGN.md §3.2). The expected `sub` is
// produced from an INDEPENDENT re-implementation of the documented encoding —
// 8-byte big-endian len(sector) || sector || userID, HMAC-SHA256 keyed by the
// per-user secret, RawURLEncoding — written out by hand here. If DerivePPID's
// encoding ever changes (e.g. the length prefix is dropped or the fields are
// reordered), the two implementations diverge and this test fails.
func TestDerivePPID_GoldenVector(t *testing.T) {
	secret := []byte("golden-pairwise-secret-0123456789")
	sector := "rp.example.com"
	userID := "user-123"

	var lenPrefix [8]byte
	binary.BigEndian.PutUint64(lenPrefix[:], uint64(len(sector)))
	msg := make([]byte, 0, 8+len(sector)+len(userID))
	msg = append(msg, lenPrefix[:]...)
	msg = append(msg, []byte(sector)...)
	msg = append(msg, []byte(userID)...)

	mac := hmac.New(sha256.New, secret)
	mac.Write(msg)
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	got := mustDerive(t, secret, sector, userID)
	if got != want {
		t.Fatalf("golden PPID mismatch: DerivePPID = %q, want %q (derivation changed?)", got, want)
	}
}

// Non-correlation: same user across DIFFERENT sectors must yield unrelated subs,
// so two RPs cannot join the user's identity.
func TestDerivePPID_NonCorrelationAcrossSectors(t *testing.T) {
	secret := []byte("user-pairwise-secret-0000000000000000")
	rp1 := mustDerive(t, secret, "rp-one.example.com", "user-123")
	rp2 := mustDerive(t, secret, "rp-two.example.com", "user-123")
	if rp1 == rp2 {
		t.Fatalf("same user in different sectors produced identical ppid %q", rp1)
	}
}

func TestDerivePPID_DifferentUsersSameSector(t *testing.T) {
	secret := []byte("user-pairwise-secret-0000000000000000")
	u1 := mustDerive(t, secret, "rp.example.com", "user-111")
	u2 := mustDerive(t, secret, "rp.example.com", "user-222")
	if u1 == u2 {
		t.Fatalf("different users in same sector produced identical ppid %q", u1)
	}
}

// The per-user secret is the HMAC key: a different secret must change the sub
// even for identical (sector, user).
func TestDerivePPID_DifferentSecret(t *testing.T) {
	a := mustDerive(t, []byte("secret-aaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "rp.example.com", "user-123")
	b := mustDerive(t, []byte("secret-bbbbbbbbbbbbbbbbbbbbbbbbbbbb"), "rp.example.com", "user-123")
	if a == b {
		t.Fatalf("different secrets produced identical ppid %q", a)
	}
}

// Ambiguity resistance: ("a","bc") and ("ab","c") would collide under naive byte
// concatenation. Length-prefixing must keep them distinct.
func TestDerivePPID_AmbiguityResistance(t *testing.T) {
	secret := []byte("user-pairwise-secret-0000000000000000")
	cases := []struct {
		name             string
		sectorA, userIDA string
		sectorB, userIDB string
	}{
		{"a|bc vs ab|c", "a", "bc", "ab", "c"},
		{"x|yz vs xy|z", "x", "yz", "xy", "z"},
		{"empty-boundary shift", "rp", "1user", "rp1", "user"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := mustDerive(t, secret, tc.sectorA, tc.userIDA)
			b := mustDerive(t, secret, tc.sectorB, tc.userIDB)
			if a == b {
				t.Fatalf("ambiguous inputs collided: (%q,%q) and (%q,%q) both -> %q",
					tc.sectorA, tc.userIDA, tc.sectorB, tc.userIDB, a)
			}
		})
	}
}

func TestDerivePPID_ValidationErrors(t *testing.T) {
	cases := []struct {
		name    string
		secret  []byte
		sector  string
		userID  string
		wantErr error
	}{
		{"empty secret", []byte{}, "rp.example.com", "user-123", ErrEmptySecret},
		{"nil secret", nil, "rp.example.com", "user-123", ErrEmptySecret},
		{"empty sector", []byte("secret"), "", "user-123", ErrEmptySector},
		{"empty user id", []byte("secret"), "rp.example.com", "", ErrEmptyUserID},
		{"secret too long", []byte(strings.Repeat("k", MaxSecretLen+1)), "rp.example.com", "user-123", ErrSecretTooLong},
		{"sector too long", []byte("secret"), strings.Repeat("s", MaxSectorLen+1), "user-123", ErrSectorTooLong},
		{"user id too long", []byte("secret"), "rp.example.com", strings.Repeat("u", MaxUserIDLen+1), ErrUserIDTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DerivePPID(tc.secret, tc.sector, tc.userID)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("DerivePPID error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// Inputs at exactly the maximum length must still succeed (the guards are
// strictly-greater-than bounds).
func TestDerivePPID_MaxLengthBoundariesOK(t *testing.T) {
	secret := []byte(strings.Repeat("k", MaxSecretLen))
	sector := strings.Repeat("s", MaxSectorLen)
	userID := strings.Repeat("u", MaxUserIDLen)
	if _, err := DerivePPID(secret, sector, userID); err != nil {
		t.Fatalf("max-length inputs should be accepted, got error: %v", err)
	}
}
