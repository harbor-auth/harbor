package crypto

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
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

// --- Full round-trip integration tests ---

// TestKMSSigningKeyRoundTripViaDBStore exercises the full production flow:
// generate KMSBackedSigner → persist wrapped private key to the signing key store →
// reload via LoadKMSBackedSigner → sign a JWT → verify signature matches.
// Uses FakeKMSClient for a hermetic test.
func TestKMSSigningKeyRoundTripViaDBStore(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"
	keyID := "arn:aws:kms:us-east-1:123456789012:key/roundtrip-key"

	// --- 1. Set up KMS-backed key provider with a fake KMS client. ---
	kmsClient := NewFakeKMSClient()
	resolver := NewStaticKEKResolver(map[string]string{region: keyID})
	kp := NewKMSKeyProvider(kmsClient, resolver)

	// --- 2. Generate a new KMS-backed signer + wrapped private key. ---
	signer, wrapped, err := NewKMSBackedSigner(ctx, kp, region)
	if err != nil {
		t.Fatalf("NewKMSBackedSigner: %v", err)
	}

	// --- 3. Persist the wrapped private key to the signing key store. ---
	store := newFakeSigningKeyStore()
	pubDER, err := jwkToPublicKeyDER(signer.PublicJWK())
	if err != nil {
		t.Fatalf("jwkToPublicKeyDER: %v", err)
	}
	if err := store.CreateKey(ctx, "key-id-1", signer.KeyID(), region, pubDER, wrapped); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// --- 4. Retrieve the persisted key and reload the signer. ---
	persisted, err := store.GetByKid(ctx, signer.KeyID())
	if err != nil {
		t.Fatalf("GetByKid: %v", err)
	}
	if len(persisted.PrivateKeyWrapped) == 0 {
		t.Fatal("persisted wrapped private key is empty")
	}

	loaded, err := LoadKMSBackedSigner(ctx, kp, region, persisted.PrivateKeyWrapped)
	if err != nil {
		t.Fatalf("LoadKMSBackedSigner: %v", err)
	}

	// --- 5. Reloaded signer must have the same key identity. ---
	if loaded.KeyID() != signer.KeyID() {
		t.Errorf("loaded KeyID = %q, want %q", loaded.KeyID(), signer.KeyID())
	}

	// --- 6. Sign a JWT-shaped signing input with the reloaded signer. ---
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT","kid":"` + loaded.KeyID() + `"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-123","iss":"harbor","aud":"test"}`))
	signingInput := []byte(header + "." + payload)

	sig, err := loaded.Sign(signingInput)
	if err != nil {
		t.Fatalf("loaded Sign: %v", err)
	}

	// --- 7. Verify the signature against the persisted public key (DER). ---
	pubAny, err := x509.ParsePKIXPublicKey(persisted.PublicKeyBytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pubAny)
	}
	if !verifySignature(pub, signingInput, sig) {
		t.Error("signature from reloaded signer failed verification against persisted public key")
	}

	// --- 8. A signature from the ORIGINAL signer must also verify (same key). ---
	origSig, err := signer.Sign(signingInput)
	if err != nil {
		t.Fatalf("original Sign: %v", err)
	}
	if !verifySignature(pub, signingInput, origSig) {
		t.Error("signature from original signer failed verification")
	}
}

// TestKMSSigningKeyRoundTripAcrossReplicas simulates two harbor-hot replicas
// (separate KMSKeyProvider instances sharing the same KMS backend) loading the
// same persisted wrapped key and producing mutually verifiable signatures.
// This is the core guarantee: signing keys are consistent across replicas.
func TestKMSSigningKeyRoundTripAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	region := "eu-west-1"
	keyID := "arn:aws:kms:eu-west-1:123456789012:key/replica-key"

	// Shared KMS backend (the KEK lives in KMS, shared across replicas).
	kmsClient := NewFakeKMSClient()
	resolver := NewStaticKEKResolver(map[string]string{region: keyID})

	// Replica A generates and persists the key.
	kpA := NewKMSKeyProvider(kmsClient, resolver)
	signerA, wrapped, err := NewKMSBackedSigner(ctx, kpA, region)
	if err != nil {
		t.Fatalf("NewKMSBackedSigner: %v", err)
	}

	store := newFakeSigningKeyStore()
	pubDER, err := jwkToPublicKeyDER(signerA.PublicJWK())
	if err != nil {
		t.Fatalf("jwkToPublicKeyDER: %v", err)
	}
	if err := store.CreateKey(ctx, "replica-key-1", signerA.KeyID(), region, pubDER, wrapped); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// Replica B loads the persisted key with a fresh provider (simulated restart).
	kpB := NewKMSKeyProvider(kmsClient, resolver)
	persisted, err := store.GetByKid(ctx, signerA.KeyID())
	if err != nil {
		t.Fatalf("GetByKid: %v", err)
	}
	signerB, err := LoadKMSBackedSigner(ctx, kpB, region, persisted.PrivateKeyWrapped)
	if err != nil {
		t.Fatalf("LoadKMSBackedSigner: %v", err)
	}

	// Both replicas must share the same key identity.
	if signerA.KeyID() != signerB.KeyID() {
		t.Errorf("replica KeyID mismatch: A=%q B=%q", signerA.KeyID(), signerB.KeyID())
	}

	// A signature from replica A verifies with replica B's public key and vice versa.
	signingInput := []byte("header.payload.cross-replica")

	sigA, err := signerA.Sign(signingInput)
	if err != nil {
		t.Fatalf("signerA Sign: %v", err)
	}
	sigB, err := signerB.Sign(signingInput)
	if err != nil {
		t.Fatalf("signerB Sign: %v", err)
	}

	pubB, err := signerB.PublicJWK().ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey: %v", err)
	}
	if !verifySignature(pubB, signingInput, sigA) {
		t.Error("replica A signature not verifiable by replica B public key")
	}
	if !verifySignature(pubB, signingInput, sigB) {
		t.Error("replica B signature not verifiable by its own public key")
	}
}

// --- Rejection / no-oracle / panic-safety tests ---

// TestKMSBackedSignerWrongRegionNoOracle verifies that loading a wrapped signing
// key under the wrong region fails with the SAME generic error as loading a
// tampered wrapped key, so there is no oracle distinguishing the two failure
// modes.
func TestKMSBackedSignerWrongRegionNoOracle(t *testing.T) {
	ctx := context.Background()
	regionA := "us-east-1"
	regionB := "eu-west-1"

	kp, err := NewLocalKeyProvider("test-secret-for-no-oracle-sign!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}

	_, wrapped, err := NewKMSBackedSigner(ctx, kp, regionA)
	if err != nil {
		t.Fatalf("NewKMSBackedSigner: %v", err)
	}

	// Wrong region (intact wrapped key).
	_, wrongRegionErr := LoadKMSBackedSigner(ctx, kp, regionB, wrapped)
	if wrongRegionErr == nil {
		t.Fatal("wrong-region load must fail")
	}

	// Tampered ciphertext (correct region).
	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 0xff
	_, tamperErr := LoadKMSBackedSigner(ctx, kp, regionA, tampered)
	if tamperErr == nil {
		t.Fatal("tampered load must fail")
	}

	// Both must wrap the same sentinel and produce identical error strings, so a
	// caller cannot distinguish a wrong region from corrupt data.
	if !errors.Is(wrongRegionErr, ErrDecryptFailed) {
		t.Errorf("wrong-region err = %v, want wraps ErrDecryptFailed", wrongRegionErr)
	}
	if !errors.Is(tamperErr, ErrDecryptFailed) {
		t.Errorf("tamper err = %v, want wraps ErrDecryptFailed", tamperErr)
	}
	if wrongRegionErr.Error() != tamperErr.Error() {
		t.Errorf("distinguishable errors (oracle signal): wrong-region=%q tamper=%q",
			wrongRegionErr.Error(), tamperErr.Error())
	}
}

// TestLoadKMSBackedSignerNoPanicOnMalformedInput verifies that loading a signer
// from malformed / short wrapped bytes never panics — it always returns an error.
func TestLoadKMSBackedSignerNoPanicOnMalformedInput(t *testing.T) {
	ctx := context.Background()
	region := "us-east-1"

	kp, err := NewLocalKeyProvider("test-secret-for-panic-safety!!!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}

	inputs := [][]byte{
		nil,
		{},
		{1},
		{1, 0},
		{1, 0, 0},
		{1, 255, 0}, // dekLen huge, no payload
		{1, 0, 1},   // dekLen=1 but no dek/ciphertext
		{wrappedKeyVersion, 0, 0},
		{99, 0, 0, 'x'}, // wrong version
		bytes.Repeat([]byte{0xff}, 8),
		bytes.Repeat([]byte{0x00}, 128),
	}

	for i, in := range inputs {
		in := in
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("LoadKMSBackedSigner[%d] panicked: %v", i, r)
				}
			}()
			if _, err := LoadKMSBackedSigner(ctx, kp, region, in); err == nil {
				t.Errorf("LoadKMSBackedSigner[%d]: expected error for malformed input", i)
			}
		}()
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
