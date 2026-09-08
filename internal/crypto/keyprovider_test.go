package crypto

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

var testCtx = context.Background()

const testSecret = "test-secret-32byteslong!!!!!!!!!"

// --- localKeyProvider tests ---

func TestNewLocalKeyProviderEmptySecretFails(t *testing.T) {
	_, err := NewLocalKeyProvider("")
	if !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("expected ErrEmptySecret, got %v", err)
	}
}

// TestNewLocalKeyProviderRejectsWeakSecret pins the fail-CLOSED boot guard on
// the user-DEK KEK. HKDF derives a usable key from any non-empty input, so
// without this every user's DEK would be wrapped under a guessable — or, for
// the manifest placeholder, a publicly published — key, and nothing would say
// so at runtime. The three binaries that build this provider previously
// checked only `secret == ""`.
func TestNewLocalKeyProviderRejectsWeakSecret(t *testing.T) {
	cases := []struct {
		name   string
		secret string
	}{
		{"one byte short of the floor", "abcdefghijklmnopqrstuvwxyz12345"},
		{"short human-chosen value", "hunter2"},
		// Both shipped placeholders clear the 32-byte floor (40 and 43 bytes),
		// so only the placeholder check catches them. The two manifests spell
		// it differently, which is why the check matches markers rather than
		// an exhaustive list of exact values.
		{"deploy/helm/values.yaml placeholder", "REPLACE_WITH_SHARED_32_BYTE_USER_DEK_KEK"},
		{"deploy/k8s/secret-*.yaml placeholder", "REPLACE_ME_WITH_SHARED_32_BYTE_USER_DEK_KEK"},
		{"long-but-obviously-a-placeholder", "CHANGEME_CHANGEME_CHANGEME_CHANGEME"},
		{"lowercase changeme is caught too", "changeme-changeme-changeme-changeme"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewLocalKeyProvider(tc.secret); !errors.Is(err, ErrWeakSecret) {
				t.Fatalf("NewLocalKeyProvider(%q) err = %v, want ErrWeakSecret", tc.secret, err)
			}
		})
	}
}

// TestNewLocalKeyProviderAcceptsStrongSecret is the false-positive guard: a
// real generated secret (the shape `openssl rand -hex 32` produces) must still
// be accepted, so the new check cannot break a correctly-configured install.
func TestNewLocalKeyProviderAcceptsStrongSecret(t *testing.T) {
	// 64 hex chars — the documented way to generate this value.
	const generated = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if _, err := NewLocalKeyProvider(generated); err != nil {
		t.Fatalf("NewLocalKeyProvider(generated secret) err = %v, want nil", err)
	}
}

// TestNewLocalKeyProviderAcceptsE2EFixture pins the local-dev fixture in
// e2e/docker-compose.yml. It reads as placeholder-ish ("change-me") but is
// hyphenated, which the marker list deliberately does NOT match: that stack is
// ephemeral, local-only, and never holds real user data, so rejecting it would
// break `docker compose up` for every developer to no security benefit.
//
// If you are here because you added "CHANGE-ME" to placeholderSecretMarkers
// and this test failed: that is the trade-off firing. Change the compose
// fixture to a generated value first, then extend the markers.
func TestNewLocalKeyProviderAcceptsE2EFixture(t *testing.T) {
	const e2eFixture = "e2e-shared-user-dek-kek-change-me" // e2e/docker-compose.yml
	if _, err := NewLocalKeyProvider(e2eFixture); err != nil {
		t.Fatalf("NewLocalKeyProvider(e2e fixture) err = %v, want nil — this would break the e2e stack", err)
	}
}

func TestLocalKeyProviderWrapUnwrapRoundTrip(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	kp, err := NewLocalKeyProvider(testSecret)
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	region := "us-east-1"
	wrapped, err := kp.WrapDEK(testCtx, region, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	// The wrapped blob must not contain the raw DEK bytes.
	if bytes.Contains(wrapped, dek[:]) {
		t.Fatal("wrapped DEK contains raw DEK bytes in the clear")
	}
	got, err := kp.UnwrapDEK(testCtx, region, wrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if got != dek {
		t.Fatalf("round-trip DEK mismatch: got %x, want %x", got, dek)
	}
}

//harbor:invariant INV-DEK-REGION-ISOLATED
func TestLocalKeyProviderRegionIsolation(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	kp, err := NewLocalKeyProvider(testSecret)
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}

	wrapped, err := kp.WrapDEK(testCtx, "eu-west-1", dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	// Unwrapping with a different region must fail (GCM AAD mismatch).
	got, err := kp.UnwrapDEK(testCtx, "us-east-1", wrapped)
	if err == nil {
		t.Fatal("cross-region UnwrapDEK must fail, got nil error")
	}
	if !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("cross-region UnwrapDEK error = %v, want ErrDecryptFailed", err)
	}
	// A zero DEK must be returned — never the original, not even partial.
	if got != (DEK{}) {
		t.Fatalf("cross-region UnwrapDEK returned non-zero DEK: %x", got)
	}
}

func TestLocalKeyProviderDifferentSecretsGiveDifferentWraps(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	kp1, err := NewLocalKeyProvider("secret-aaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider#1: %v", err)
	}
	kp2, err := NewLocalKeyProvider("secret-bbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider#2: %v", err)
	}
	region := "us-east-1"
	w1, err := kp1.WrapDEK(testCtx, region, dek)
	if err != nil {
		t.Fatalf("WrapDEK#1: %v", err)
	}
	w2, err := kp2.WrapDEK(testCtx, region, dek)
	if err != nil {
		t.Fatalf("WrapDEK#2: %v", err)
	}
	if bytes.Equal(w1, w2) {
		t.Fatal("different secrets produced identical wrapped DEK")
	}
	// kp1 must not be able to unwrap kp2's wrapped DEK.
	if _, err := kp1.UnwrapDEK(testCtx, region, w2); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("kp1 unwrapping kp2's DEK: error = %v, want ErrDecryptFailed", err)
	}
}

func TestLocalKeyProviderTamperedWrappedDEK(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	kp, err := NewLocalKeyProvider(testSecret)
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	wrapped, err := kp.WrapDEK(testCtx, "us-east-1", dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 0xff
	got, err := kp.UnwrapDEK(testCtx, "us-east-1", tampered)
	if !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("tampered wrapped DEK: error = %v, want ErrDecryptFailed", err)
	}
	if got != (DEK{}) {
		t.Fatalf("tampered unwrap returned non-zero DEK: %x", got)
	}
}

func TestLocalKeyProviderStringIsSelfIdentifying(t *testing.T) {
	kp, err := NewLocalKeyProvider(testSecret)
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	s, ok := kp.(interface{ String() string })
	if !ok {
		t.Fatal("localKeyProvider does not implement String()")
	}
	if s.String() != "localKeyProvider(DEV-ONLY)" {
		t.Fatalf("String() = %q, want localKeyProvider(DEV-ONLY)", s.String())
	}
}

// --- kmsKeyProvider scaffold tests ---

func TestKMSKeyProviderNotImplemented(t *testing.T) {
	kp := &kmsKeyProvider{}
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}
	if _, err := kp.WrapDEK(testCtx, "us-east-1", dek); !errors.Is(err, ErrKMSNotImplemented) {
		t.Fatalf("WrapDEK error = %v, want ErrKMSNotImplemented", err)
	}
	if _, err := kp.UnwrapDEK(testCtx, "us-east-1", []byte("blob")); !errors.Is(err, ErrKMSNotImplemented) {
		t.Fatalf("UnwrapDEK error = %v, want ErrKMSNotImplemented", err)
	}
}

// Compile-time assertion that both providers satisfy the KeyProvider interface.
var (
	_ KeyProvider = (*localKeyProvider)(nil)
	_ KeyProvider = (*kmsKeyProvider)(nil)
)
