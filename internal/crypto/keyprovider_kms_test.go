package crypto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

// TestKMSKeyProviderWrongRegionNoOracle verifies that unwrapping a DEK with the
// wrong region returns the SAME generic error as unwrapping corrupt ciphertext,
// so an attacker cannot distinguish "wrong region" from "corrupt data" (no
// decryption oracle signal).
func TestKMSKeyProviderWrongRegionNoOracle(t *testing.T) {
	ctx := context.Background()
	regionA := "us-east-1"
	regionB := "eu-west-1"

	kmsClient := NewFakeKMSClient()
	resolver := NewStaticKEKResolver(map[string]string{
		regionA: "kek-a",
		regionB: "kek-b",
	})
	provider := NewKMSKeyProvider(kmsClient, resolver)

	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}

	wrapped, err := provider.WrapDEK(ctx, regionA, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	// Case 1: wrong region (correct, intact envelope).
	_, wrongRegionErr := provider.UnwrapDEK(ctx, regionB, wrapped)
	if !errors.Is(wrongRegionErr, ErrDecryptFailed) {
		t.Fatalf("wrong-region error = %v, want ErrDecryptFailed", wrongRegionErr)
	}

	// Case 2: tampered ciphertext (correct region).
	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 0xff
	_, tamperErr := provider.UnwrapDEK(ctx, regionA, tampered)
	if !errors.Is(tamperErr, ErrDecryptFailed) {
		t.Fatalf("tamper error = %v, want ErrDecryptFailed", tamperErr)
	}

	// No oracle: both failure modes must produce an identical error string, so a
	// caller cannot tell whether the region was wrong or the data was corrupt.
	if wrongRegionErr.Error() != tamperErr.Error() {
		t.Errorf("distinguishable errors (oracle signal): wrong-region=%q tamper=%q",
			wrongRegionErr.Error(), tamperErr.Error())
	}
}

// TestKMSKeyProviderTamperedHeader verifies that tampering the envelope HEADER
// (the region or KEK key-ID bytes) — not just the ciphertext — is rejected with
// the generic ErrDecryptFailed and returns a zero DEK.
func TestKMSKeyProviderTamperedHeader(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"
	keyID := "kek-key-1"

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

	// Envelope layout:
	//   version(1) | region_len(1) | region | keyID_len(1) | keyID | ciphertext
	// Index 2 is the first byte of the region field.
	// Index (2 + len(region) + 1) is the first byte of the keyID field.
	regionByteIdx := 2
	keyIDByteIdx := 2 + len(region) + 1

	cases := []struct {
		name string
		idx  int
	}{
		{"region field", regionByteIdx},
		{"kek key-id field", keyIDByteIdx},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := append([]byte(nil), wrapped...)
			tampered[tc.idx] ^= 0xff
			got, err := provider.UnwrapDEK(ctx, region, tampered)
			if !errors.Is(err, ErrDecryptFailed) {
				t.Errorf("error = %v, want ErrDecryptFailed", err)
			}
			if got != (DEK{}) {
				t.Errorf("returned non-zero DEK: %x", got)
			}
		})
	}
}

// TestKMSKeyProviderNoCrossRegionKEKFallback verifies that a DEK wrapped for one
// region can NEVER be unwrapped under any OTHER configured region — the provider
// must never silently fall back to a different region's KEK.
func TestKMSKeyProviderNoCrossRegionKEKFallback(t *testing.T) {
	ctx := context.Background()

	regions := map[string]string{
		"us-east-1":      "kek-us",
		"eu-west-1":      "kek-eu",
		"ap-southeast-1": "kek-ap",
	}

	kmsClient := NewFakeKMSClient()
	resolver := NewStaticKEKResolver(regions)
	provider := NewKMSKeyProvider(kmsClient, resolver)

	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}

	origin := "us-east-1"
	wrapped, err := provider.WrapDEK(ctx, origin, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	// Sanity: unwrapping under the origin region succeeds.
	got, err := provider.UnwrapDEK(ctx, origin, wrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK(origin): %v", err)
	}
	if got != dek {
		t.Fatalf("origin round-trip DEK mismatch")
	}

	// Every OTHER region must fail closed — no KEK fallback, no leaked DEK.
	for region := range regions {
		if region == origin {
			continue
		}
		got, err := provider.UnwrapDEK(ctx, region, wrapped)
		if !errors.Is(err, ErrDecryptFailed) {
			t.Errorf("region %q: error = %v, want ErrDecryptFailed (no fallback)", region, err)
		}
		if got != (DEK{}) {
			t.Errorf("region %q: returned non-zero DEK: %x (KEK fallback leaked)", region, got)
		}
	}
}

// TestKMSKeyProviderNoPanicOnMalformedInput feeds a wide range of malformed and
// short byte slices to every envelope-parsing entry point and verifies none of
// them panic — they must all fail gracefully with an error.
func TestKMSKeyProviderNoPanicOnMalformedInput(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"
	keyID := "kek-1"

	kmsClient := NewFakeKMSClient()
	resolver := NewStaticKEKResolver(map[string]string{region: keyID})
	provider := NewKMSKeyProvider(kmsClient, resolver)

	// Representative set of malformed / boundary inputs.
	inputs := [][]byte{
		nil,
		{},
		{1},
		{1, 0},
		{1, 0, 0},
		{1, 255},            // region_len=255 but no region bytes
		{1, 1, 'r'},         // region present but no keyID_len
		{1, 1, 'r', 255},    // keyID_len=255 but no keyID bytes
		{1, 1, 'r', 1, 'k'}, // valid header, empty ciphertext
		{1, 0, 1, 'k'},      // zero-length region
		{0, 0, 0, 0},        // version 0
		{99, 0, 0, 0},       // unknown version
		bytes.Repeat([]byte{0xff}, 4),
		bytes.Repeat([]byte{0x00}, 64),
	}

	assertNoPanic := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%s panicked: %v", name, r)
			}
		}()
		fn()
	}

	for i, in := range inputs {
		in := in
		assertNoPanic(fmt.Sprintf("UnwrapDEK[%d]", i), func() {
			_, _ = provider.UnwrapDEK(ctx, region, in)
		})
		assertNoPanic(fmt.Sprintf("RewrapDEK[%d]", i), func() {
			_, _ = provider.RewrapDEK(ctx, region, in)
		})
		assertNoPanic(fmt.Sprintf("ParseEnvelopeInfo[%d]", i), func() {
			_, _ = ParseEnvelopeInfo(in)
		})
		assertNoPanic(fmt.Sprintf("parseEnvelope[%d]", i), func() {
			_, _, _, _ = parseEnvelope(in)
		})
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

// --- RewrapDEK tests ---

func TestKMSKeyProviderRewrapDEK(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"
	oldKeyID := "old-kek"
	newKeyID := "new-kek"

	kmsClient := NewFakeKMSClient()

	// Wrap DEK with old KEK.
	oldResolver := NewStaticKEKResolver(map[string]string{region: oldKeyID})
	oldProvider := NewKMSKeyProvider(kmsClient, oldResolver)

	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}

	oldWrapped, err := oldProvider.WrapDEK(ctx, region, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	// Verify old envelope has old KEK.
	oldInfo, _ := ParseEnvelopeInfo(oldWrapped)
	if oldInfo.KEKKeyID != oldKeyID {
		t.Fatalf("old envelope KEK = %q, want %q", oldInfo.KEKKeyID, oldKeyID)
	}

	// Create provider with new KEK.
	newResolver := NewStaticKEKResolver(map[string]string{region: newKeyID})
	newProvider := NewKMSKeyProvider(kmsClient, newResolver)

	// Rewrap under new KEK.
	newWrapped, err := newProvider.RewrapDEK(ctx, region, oldWrapped)
	if err != nil {
		t.Fatalf("RewrapDEK: %v", err)
	}

	// Verify new envelope has new KEK.
	newInfo, _ := ParseEnvelopeInfo(newWrapped)
	if newInfo.KEKKeyID != newKeyID {
		t.Errorf("new envelope KEK = %q, want %q", newInfo.KEKKeyID, newKeyID)
	}
	if newInfo.Region != region {
		t.Errorf("new envelope region = %q, want %q", newInfo.Region, region)
	}

	// Unwrap with new provider and verify DEK is preserved.
	unwrapped, err := newProvider.UnwrapDEK(ctx, region, newWrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK after rewrap: %v", err)
	}
	if unwrapped != dek {
		t.Fatalf("DEK mismatch after rewrap: got %x, want %x", unwrapped, dek)
	}
}

func TestKMSKeyProviderRewrapDEKNoChangeNeeded(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"
	keyID := "same-kek"

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

	// Rewrap with same KEK should return original envelope unchanged.
	rewrapped, err := provider.RewrapDEK(ctx, region, wrapped)
	if err != nil {
		t.Fatalf("RewrapDEK: %v", err)
	}

	// Should be exactly the same bytes.
	if !bytes.Equal(rewrapped, wrapped) {
		t.Error("RewrapDEK with same KEK should return identical envelope")
	}
}

func TestKMSKeyProviderRewrapDEKRegionMismatch(t *testing.T) {
	ctx := context.Background()
	regionA := "us-east-1"
	regionB := "eu-west-1"
	keyA := "key-a"
	keyB := "key-b"

	kmsClient := NewFakeKMSClient()

	// Wrap in region A.
	resolverA := NewStaticKEKResolver(map[string]string{regionA: keyA})
	providerA := NewKMSKeyProvider(kmsClient, resolverA)

	dek, _ := GenerateDEK()
	wrapped, _ := providerA.WrapDEK(ctx, regionA, dek)

	// Try to rewrap with region B - should fail.
	resolverB := NewStaticKEKResolver(map[string]string{regionB: keyB})
	providerB := NewKMSKeyProvider(kmsClient, resolverB)

	_, err := providerB.RewrapDEK(ctx, regionB, wrapped)
	if !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("cross-region RewrapDEK error = %v, want ErrDecryptFailed", err)
	}
}

func TestKMSKeyProviderRewrapDEKInvalidEnvelope(t *testing.T) {
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := provider.RewrapDEK(ctx, region, tc.envelope)
			if !errors.Is(err, ErrDecryptFailed) {
				t.Errorf("error = %v, want ErrDecryptFailed", err)
			}
		})
	}
}

func TestKMSKeyProviderRewrapDEKPreservesDEK(t *testing.T) {
	// This test verifies that the DEK plaintext is correctly preserved
	// through the rewrap process by checking the decrypted value.
	ctx := context.Background()
	region := "us-east-1"
	oldKeyID := "old-kek"
	newKeyID := "new-kek"

	kmsClient := NewFakeKMSClient()

	// Create a known DEK.
	var dek DEK
	for i := range dek {
		dek[i] = byte(i)
	}

	// Wrap with old KEK.
	oldResolver := NewStaticKEKResolver(map[string]string{region: oldKeyID})
	oldProvider := NewKMSKeyProvider(kmsClient, oldResolver)
	oldWrapped, _ := oldProvider.WrapDEK(ctx, region, dek)

	// Rewrap with new KEK.
	newResolver := NewStaticKEKResolver(map[string]string{region: newKeyID})
	newProvider := NewKMSKeyProvider(kmsClient, newResolver)
	newWrapped, err := newProvider.RewrapDEK(ctx, region, oldWrapped)
	if err != nil {
		t.Fatalf("RewrapDEK: %v", err)
	}

	// Verify DEK is preserved exactly.
	unwrapped, err := newProvider.UnwrapDEK(ctx, region, newWrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	for i := range unwrapped {
		if unwrapped[i] != byte(i) {
			t.Fatalf("DEK byte %d = %d, want %d", i, unwrapped[i], i)
		}
	}
}

// Compile-time assertion that KMSKeyProvider satisfies KeyProvider.
var _ KeyProvider = (*KMSKeyProvider)(nil)
