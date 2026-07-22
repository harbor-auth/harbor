package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"math/big"
	"testing"
)

// verifySignature verifies an ES256 signature against a public key.
// Test-only helper.
func verifySignature(pub *ecdsa.PublicKey, signingInput, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}
	digest := sha256.Sum256(signingInput)
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	return ecdsa.Verify(pub, digest[:], r, s)
}

// --- KMSBackedSigner tests ---

func TestKMSBackedSignerNewAndLoad(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"

	// Use localKeyProvider for testing (simulates KMS).
	kp, err := NewLocalKeyProvider("test-secret-32-bytes-long!!!!!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}

	// Create a new signer.
	signer, wrapped, err := NewKMSBackedSigner(ctx, kp, region)
	if err != nil {
		t.Fatalf("NewKMSBackedSigner: %v", err)
	}

	// Verify signer is usable.
	if signer.KeyID() == "" {
		t.Error("KeyID is empty")
	}
	jwk := signer.PublicJWK()
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.Alg != "ES256" {
		t.Errorf("unexpected JWK: %+v", jwk)
	}

	// Sign something.
	signingInput := []byte("header.payload")
	sig, err := signer.Sign(signingInput)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("signature length = %d, want 64", len(sig))
	}

	// Verify signature.
	pub, err := jwk.ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey: %v", err)
	}
	if !verifySignature(pub, signingInput, sig) {
		t.Error("signature verification failed")
	}

	// Load signer from wrapped bytes.
	loaded, err := LoadKMSBackedSigner(ctx, kp, region, wrapped)
	if err != nil {
		t.Fatalf("LoadKMSBackedSigner: %v", err)
	}

	// Verify loaded signer has same KeyID.
	if loaded.KeyID() != signer.KeyID() {
		t.Errorf("loaded KeyID = %q, want %q", loaded.KeyID(), signer.KeyID())
	}

	// Verify loaded signer can sign.
	sig2, err := loaded.Sign(signingInput)
	if err != nil {
		t.Fatalf("loaded Sign: %v", err)
	}

	// Verify signature from loaded signer.
	if !verifySignature(pub, signingInput, sig2) {
		t.Error("loaded signer signature verification failed")
	}
}

func TestKMSBackedSignerKeyIDStability(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"

	kp, err := NewLocalKeyProvider("test-secret-for-stability-test!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}

	signer, wrapped, err := NewKMSBackedSigner(ctx, kp, region)
	if err != nil {
		t.Fatalf("NewKMSBackedSigner: %v", err)
	}

	// Load multiple times and verify KeyID is stable.
	for i := range 3 {
		loaded, err := LoadKMSBackedSigner(ctx, kp, region, wrapped)
		if err != nil {
			t.Fatalf("LoadKMSBackedSigner[%d]: %v", i, err)
		}
		if loaded.KeyID() != signer.KeyID() {
			t.Errorf("load[%d] KeyID = %q, want %q", i, loaded.KeyID(), signer.KeyID())
		}
	}
}

//harbor:invariant INV-SIGNING-KEY-REGION-ISOLATED
func TestKMSBackedSignerRegionIsolation(t *testing.T) {
	ctx := context.Background()
	regionA := "us-east-1"
	regionB := "eu-west-1"

	kp, err := NewLocalKeyProvider("test-secret-for-region-test!!!!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}

	// Create signer in region A.
	_, wrapped, err := NewKMSBackedSigner(ctx, kp, regionA)
	if err != nil {
		t.Fatalf("NewKMSBackedSigner: %v", err)
	}

	// Try to load in region B - must fail.
	_, err = LoadKMSBackedSigner(ctx, kp, regionB, wrapped)
	if err == nil {
		t.Fatal("cross-region LoadKMSBackedSigner should fail")
	}
}

func TestKMSBackedSignerTamperedWrappedKey(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"

	kp, err := NewLocalKeyProvider("test-secret-for-tamper-test!!!!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}

	_, wrapped, err := NewKMSBackedSigner(ctx, kp, region)
	if err != nil {
		t.Fatalf("NewKMSBackedSigner: %v", err)
	}

	// Tamper with the wrapped bytes.
	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 0xff

	_, err = LoadKMSBackedSigner(ctx, kp, region, tampered)
	if err == nil {
		t.Fatal("tampered LoadKMSBackedSigner should fail")
	}
}

func TestKMSBackedSignerInvalidWrappedKey(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"

	kp, err := NewLocalKeyProvider("test-secret-for-invalid-test!!!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}

	testCases := []struct {
		name    string
		wrapped []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{1, 2, 3}},
		{"wrong version", []byte{99, 0, 1, 'x', 'y'}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadKMSBackedSigner(ctx, kp, region, tc.wrapped)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestKMSBackedSignerString(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"

	kp, err := NewLocalKeyProvider("test-secret-for-string-test!!!!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}

	signer, _, err := NewKMSBackedSigner(ctx, kp, region)
	if err != nil {
		t.Fatalf("NewKMSBackedSigner: %v", err)
	}

	if signer.String() != "KMSBackedSigner" {
		t.Errorf("String() = %q, want %q", signer.String(), "KMSBackedSigner")
	}
}

func TestKMSBackedSignerSignatureFormat(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"

	kp, err := NewLocalKeyProvider("test-secret-for-sig-format-test")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}

	signer, _, err := NewKMSBackedSigner(ctx, kp, region)
	if err != nil {
		t.Fatalf("NewKMSBackedSigner: %v", err)
	}

	// Sign multiple inputs and verify format.
	for i := range 10 {
		input := []byte{byte(i), byte(i + 1), byte(i + 2)}
		sig, err := signer.Sign(input)
		if err != nil {
			t.Fatalf("Sign[%d]: %v", i, err)
		}
		if len(sig) != 64 {
			t.Errorf("Sign[%d] len = %d, want 64", i, len(sig))
		}
	}
}

func TestKMSBackedSignerJWKRoundTrip(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"

	kp, err := NewLocalKeyProvider("test-secret-for-jwk-roundtrip!!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}

	signer, _, err := NewKMSBackedSigner(ctx, kp, region)
	if err != nil {
		t.Fatalf("NewKMSBackedSigner: %v", err)
	}

	jwk := signer.PublicJWK()

	// Verify JWK fields.
	if jwk.Kty != "EC" {
		t.Errorf("Kty = %q, want EC", jwk.Kty)
	}
	if jwk.Crv != "P-256" {
		t.Errorf("Crv = %q, want P-256", jwk.Crv)
	}
	if jwk.Use != "sig" {
		t.Errorf("Use = %q, want sig", jwk.Use)
	}
	if jwk.Alg != "ES256" {
		t.Errorf("Alg = %q, want ES256", jwk.Alg)
	}
	if jwk.Kid != signer.KeyID() {
		t.Errorf("Kid = %q, want %q", jwk.Kid, signer.KeyID())
	}

	// Reconstruct public key and verify signature.
	pub, err := jwk.ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey: %v", err)
	}

	input := []byte("test data for jwk round-trip")
	sig, err := signer.Sign(input)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify using raw ECDSA.
	digest := sha256.Sum256(input)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Error("ECDSA verification failed")
	}
}

func TestVerifySignature(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"

	kp, err := NewLocalKeyProvider("test-secret-for-verify-sig-test")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}

	signer, _, err := NewKMSBackedSigner(ctx, kp, region)
	if err != nil {
		t.Fatalf("NewKMSBackedSigner: %v", err)
	}

	pub, err := signer.PublicJWK().ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey: %v", err)
	}

	input := []byte("test data")
	sig, err := signer.Sign(input)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Valid signature.
	if !verifySignature(pub, input, sig) {
		t.Error("valid signature rejected")
	}

	// Wrong input.
	if verifySignature(pub, []byte("wrong data"), sig) {
		t.Error("signature verified with wrong input")
	}

	// Tampered signature.
	tamperedSig := append([]byte(nil), sig...)
	tamperedSig[0] ^= 0xff
	if verifySignature(pub, input, tamperedSig) {
		t.Error("tampered signature verified")
	}

	// Wrong length signature.
	if verifySignature(pub, input, []byte("short")) {
		t.Error("short signature verified")
	}
}

func TestKMSBackedSignerWithKMSKeyProvider(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"
	keyID := "arn:aws:kms:us-east-1:123456789012:key/test-key"

	// Use FakeKMSClient with KMSKeyProvider.
	kmsClient := NewFakeKMSClient()
	resolver := NewStaticKEKResolver(map[string]string{region: keyID})
	kp := NewKMSKeyProvider(kmsClient, resolver)

	// Create a new signer.
	signer, wrapped, err := NewKMSBackedSigner(ctx, kp, region)
	if err != nil {
		t.Fatalf("NewKMSBackedSigner: %v", err)
	}

	// Verify signer works.
	input := []byte("header.payload")
	sig, err := signer.Sign(input)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pub, err := signer.PublicJWK().ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey: %v", err)
	}

	if !verifySignature(pub, input, sig) {
		t.Error("signature verification failed")
	}

	// Load signer from wrapped bytes.
	loaded, err := LoadKMSBackedSigner(ctx, kp, region, wrapped)
	if err != nil {
		t.Fatalf("LoadKMSBackedSigner: %v", err)
	}

	if loaded.KeyID() != signer.KeyID() {
		t.Errorf("loaded KeyID mismatch")
	}
}

func TestKMSBackedSignerDifferentKeysPerRegion(t *testing.T) {
	ctx := context.Background()

	kp, err := NewLocalKeyProvider("test-secret-for-multi-region-!!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}

	regions := []string{"us-east-1", "eu-west-1", "ap-southeast-1"}
	signers := make(map[string]*KMSBackedSigner)
	wrappedKeys := make(map[string][]byte)

	// Create signers for each region.
	for _, region := range regions {
		signer, wrapped, err := NewKMSBackedSigner(ctx, kp, region)
		if err != nil {
			t.Fatalf("NewKMSBackedSigner(%s): %v", region, err)
		}
		signers[region] = signer
		wrappedKeys[region] = wrapped
	}

	// Verify each signer has a unique KeyID.
	kids := make(map[string]bool)
	for region, signer := range signers {
		kid := signer.KeyID()
		if kids[kid] {
			t.Errorf("duplicate KeyID across regions: %s", kid)
		}
		kids[kid] = true

		// Verify can only load in same region.
		loaded, err := LoadKMSBackedSigner(ctx, kp, region, wrappedKeys[region])
		if err != nil {
			t.Errorf("LoadKMSBackedSigner(%s): %v", region, err)
		}
		if loaded.KeyID() != kid {
			t.Errorf("loaded KeyID mismatch for %s", region)
		}
	}
}
