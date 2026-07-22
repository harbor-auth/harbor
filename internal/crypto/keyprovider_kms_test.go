package crypto

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// buildEnvelope is a test helper to construct versioned envelopes manually.
func buildEnvelope(version byte, region, keyID string, ciphertext []byte) []byte {
	buf := make([]byte, 0, 3+len(region)+len(keyID)+len(ciphertext))
	buf = append(buf, version)
	buf = append(buf, byte(len(region)))
	buf = append(buf, []byte(region)...)
	buf = append(buf, byte(len(keyID)))
	buf = append(buf, []byte(keyID)...)
	buf = append(buf, ciphertext...)
	return buf
}

// --- KMSKeyProvider tests ---

func TestKMSKeyProviderWrapUnwrapRoundTrip(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"
	keyID := "arn:aws:kms:us-east-1:123456789012:key/test-key"

	kmsClient := NewFakeKMSClient()
	resolver := NewStaticKEKResolver(map[string]string{region: keyID})
	provider := NewKMSKeyProvider(kmsClient, resolver)

	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}

	wrapped, err := provider.WrapDEK(ctx, region, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	// Wrapped blob must not contain raw DEK bytes.
	if bytes.Contains(wrapped, dek[:]) {
		t.Fatal("wrapped DEK contains raw DEK bytes in the clear")
	}

	// Unwrap and verify.
	got, err := provider.UnwrapDEK(ctx, region, wrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}

	if got != dek {
		t.Fatalf("round-trip DEK mismatch: got %x, want %x", got, dek)
	}
}

func TestKMSKeyProviderEnvelopeContainsMetadata(t *testing.T) {
	ctx := context.Background()
	region := "eu-west-1"
	keyID := "alias/harbor-kek-eu"

	kmsClient := NewFakeKMSClient()
	resolver := NewStaticKEKResolver(map[string]string{region: keyID})
	provider := NewKMSKeyProvider(kmsClient, resolver)

	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}

	wrapped, err := provider.WrapDEK(ctx, region, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	// Parse envelope info.
	info, err := ParseEnvelopeInfo(wrapped)
	if err != nil {
		t.Fatalf("ParseEnvelopeInfo: %v", err)
	}

	if info.Version != 1 {
		t.Errorf("Version = %d, want 1", info.Version)
	}
	if info.Region != region {
		t.Errorf("Region = %q, want %q", info.Region, region)
	}
	if info.KEKKeyID != keyID {
		t.Errorf("KEKKeyID = %q, want %q", info.KEKKeyID, keyID)
	}
}

//harbor:invariant INV-DEK-REGION-ISOLATED
func TestKMSKeyProviderRegionIsolation(t *testing.T) {
	ctx := context.Background()
	regionA := "us-east-1"
	regionB := "eu-west-1"
	keyA := "arn:aws:kms:us-east-1:123456789012:key/key-a"
	keyB := "arn:aws:kms:eu-west-1:123456789012:key/key-b"

	kmsClient := NewFakeKMSClient()
	resolver := NewStaticKEKResolver(map[string]string{
		regionA: keyA,
		regionB: keyB,
	})
	provider := NewKMSKeyProvider(kmsClient, resolver)

	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}

	// Wrap in region A.
	wrapped, err := provider.WrapDEK(ctx, regionA, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	// Unwrapping with region B must fail.
	got, err := provider.UnwrapDEK(ctx, regionB, wrapped)
	if err == nil {
		t.Fatal("cross-region UnwrapDEK must fail, got nil error")
	}
	if !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("cross-region UnwrapDEK error = %v, want ErrDecryptFailed", err)
	}
	// A zero DEK must be returned.
	if got != (DEK{}) {
		t.Fatalf("cross-region UnwrapDEK returned non-zero DEK: %x", got)
	}
}

func TestKMSKeyProviderUnknownRegion(t *testing.T) {
	ctx := context.Background()
	kmsClient := NewFakeKMSClient()
	resolver := NewStaticKEKResolver(map[string]string{
		"us-east-1": "key-1",
	})
	provider := NewKMSKeyProvider(kmsClient, resolver)

	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}

	// WrapDEK with unknown region should fail.
	_, err = provider.WrapDEK(ctx, "unknown-region", dek)
	if err == nil {
		t.Fatal("expected error for unknown region, got nil")
	}
}

func TestKMSKeyProviderTamperedEnvelope(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"
	keyID := "key-1"

	kmsClient := NewFakeKMSClient()
	resolver := NewStaticKEKResolver(map[string]string{region: keyID})
	provider := NewKMSKeyProvider(kmsClient, resolver)

	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}

	wrapped, err := provider.WrapDEK(ctx, region, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	// Tamper with the last byte (ciphertext).
	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 0xff

	got, err := provider.UnwrapDEK(ctx, region, tampered)
	if !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("tampered envelope: error = %v, want ErrDecryptFailed", err)
	}
	if got != (DEK{}) {
		t.Fatalf("tampered unwrap returned non-zero DEK: %x", got)
	}
}

func TestKMSKeyProviderInvalidEnvelope(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"
	keyID := "key-1"

	kmsClient := NewFakeKMSClient()
	resolver := NewStaticKEKResolver(map[string]string{region: keyID})
	provider := NewKMSKeyProvider(kmsClient, resolver)

	testCases := []struct {
		name     string
		envelope []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{1, 2}},
		{"wrong version", buildEnvelope(99, region, keyID, []byte("ct"))},
		{"truncated region", []byte{1, 100, 'a'}}, // region_len=100 but only 1 byte
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := provider.UnwrapDEK(ctx, region, tc.envelope)
			if !errors.Is(err, ErrDecryptFailed) {
				t.Errorf("error = %v, want ErrDecryptFailed", err)
			}
			if got != (DEK{}) {
				t.Errorf("returned non-zero DEK: %x", got)
			}
		})
	}
}

func TestKMSKeyProviderKEKKeyMismatch(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"
	oldKeyID := "old-key"
	newKeyID := "new-key"

	kmsClient := NewFakeKMSClient()

	// Wrap with old key.
	oldResolver := NewStaticKEKResolver(map[string]string{region: oldKeyID})
	oldProvider := NewKMSKeyProvider(kmsClient, oldResolver)

	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}

	wrapped, err := oldProvider.WrapDEK(ctx, region, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	// Try to unwrap with provider configured for new key.
	newResolver := NewStaticKEKResolver(map[string]string{region: newKeyID})
	newProvider := NewKMSKeyProvider(kmsClient, newResolver)

	got, err := newProvider.UnwrapDEK(ctx, region, wrapped)
	if !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("KEK mismatch: error = %v, want ErrDecryptFailed", err)
	}
	if got != (DEK{}) {
		t.Fatalf("KEK mismatch returned non-zero DEK: %x", got)
	}
}

func TestKMSKeyProviderString(t *testing.T) {
	provider := NewKMSKeyProvider(NewFakeKMSClient(), NewStaticKEKResolver(nil))
	if provider.String() != "KMSKeyProvider" {
		t.Errorf("String() = %q, want %q", provider.String(), "KMSKeyProvider")
	}
}

// --- StaticKEKResolver tests ---

func TestStaticKEKResolverSuccess(t *testing.T) {
	resolver := NewStaticKEKResolver(map[string]string{
		"us-east-1": "key-1",
		"eu-west-1": "key-2",
	})

	keyID, err := resolver.ResolveKEK("us-east-1")
	if err != nil {
		t.Fatalf("ResolveKEK: %v", err)
	}
	if keyID != "key-1" {
		t.Errorf("keyID = %q, want %q", keyID, "key-1")
	}
}

func TestStaticKEKResolverUnknownRegion(t *testing.T) {
	resolver := NewStaticKEKResolver(map[string]string{
		"us-east-1": "key-1",
	})

	_, err := resolver.ResolveKEK("unknown")
	if err == nil {
		t.Fatal("expected error for unknown region")
	}
}

// --- parseEnvelope tests ---

func TestParseEnvelopeValid(t *testing.T) {
	region := "us-east-1"
	keyID := "key-123"
	ciphertext := []byte("encrypted-data")

	envelope := buildEnvelope(1, region, keyID, ciphertext)

	gotRegion, gotKeyID, gotCT, err := parseEnvelope(envelope)
	if err != nil {
		t.Fatalf("parseEnvelope: %v", err)
	}
	if gotRegion != region {
		t.Errorf("region = %q, want %q", gotRegion, region)
	}
	if gotKeyID != keyID {
		t.Errorf("keyID = %q, want %q", gotKeyID, keyID)
	}
	if !bytes.Equal(gotCT, ciphertext) {
		t.Errorf("ciphertext mismatch")
	}
}

func TestParseEnvelopeInvalid(t *testing.T) {
	testCases := []struct {
		name     string
		envelope []byte
		wantErr  error
	}{
		{"empty", []byte{}, ErrInvalidEnvelope},
		{"too short", []byte{1, 2, 3}, ErrInvalidEnvelope},
		{"wrong version", buildEnvelope(2, "r", "k", []byte("c")), ErrEnvelopeVersionMismatch},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := parseEnvelope(tc.envelope)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseEnvelopeInfoValid(t *testing.T) {
	region := "ap-southeast-1"
	keyID := "alias/my-kek"
	envelope := buildEnvelope(1, region, keyID, []byte("ct"))

	info, err := ParseEnvelopeInfo(envelope)
	if err != nil {
		t.Fatalf("ParseEnvelopeInfo: %v", err)
	}
	if info.Version != 1 {
		t.Errorf("Version = %d, want 1", info.Version)
	}
	if info.Region != region {
		t.Errorf("Region = %q, want %q", info.Region, region)
	}
	if info.KEKKeyID != keyID {
		t.Errorf("KEKKeyID = %q, want %q", info.KEKKeyID, keyID)
	}
}

func TestParseEnvelopeInfoInvalid(t *testing.T) {
	_, err := ParseEnvelopeInfo([]byte{})
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("error = %v, want ErrInvalidEnvelope", err)
	}

	_, err = ParseEnvelopeInfo([]byte{99, 0, 0, 0}) // wrong version
	if !errors.Is(err, ErrEnvelopeVersionMismatch) {
		t.Errorf("error = %v, want ErrEnvelopeVersionMismatch", err)
	}
}

// Compile-time assertion that KMSKeyProvider satisfies KeyProvider.
var _ KeyProvider = (*KMSKeyProvider)(nil)
