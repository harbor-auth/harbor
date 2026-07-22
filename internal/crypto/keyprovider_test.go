package crypto

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

var testCtx = context.Background()

const testSecret = "test-secret-32byteslong!!!!!!!!"

// --- localKeyProvider tests ---

func TestNewLocalKeyProviderEmptySecretFails(t *testing.T) {
	_, err := NewLocalKeyProvider("")
	if !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("expected ErrEmptySecret, got %v", err)
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
