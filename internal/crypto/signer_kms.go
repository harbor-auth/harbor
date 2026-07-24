package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// KMSBackedSigner is a production Signer that holds an in-memory ECDSA private
// key whose serialized form is persisted as a KMS-wrapped blob. The private key
// is encrypted at rest using the regional KEK via KeyProvider.
//
// Unlike LocalSigner (dev-only), KMSBackedSigner is designed for production:
// the private key is protected by KMS envelope encryption, and the wrapped
// bytes can be stored in the database for persistence across restarts.
//
// KMSBackedSigner is safe for concurrent use; the underlying ECDSA operations
// are stateless.
type KMSBackedSigner struct {
	priv *ecdsa.PrivateKey
	jwk  JWK
	kid  string
}

// Compile-time proof that KMSBackedSigner implements Signer.
var _ Signer = (*KMSBackedSigner)(nil)

// NewKMSBackedSigner generates a fresh P-256 signing key, wraps it using the
// KeyProvider for the given region, and returns the signer plus the wrapped
// private key bytes for database persistence.
//
// The wrapped bytes should be stored in the database (e.g., signing_keys table)
// and can be used with LoadKMSBackedSigner to reconstruct the signer on startup.
func NewKMSBackedSigner(ctx context.Context, kp KeyProvider, region string) (*KMSBackedSigner, []byte, error) {
	// Generate a fresh P-256 private key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: KMSBackedSigner: generate key: %w", err)
	}

	// Serialize the private key to PKCS#8 DER format.
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: KMSBackedSigner: marshal private key: %w", err)
	}

	// Wrap the serialized private key using the KeyProvider.
	// We use a DEK derived from the private key bytes for wrapping.
	// The KeyProvider will encrypt this under the regional KEK.
	wrapped, err := wrapPrivateKey(ctx, kp, region, privDER)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: KMSBackedSigner: wrap key: %w", err)
	}

	signer := newKMSBackedSignerFromKey(priv)
	return signer, wrapped, nil
}

// LoadKMSBackedSigner reconstructs a KMSBackedSigner from wrapped private key
// bytes that were previously created by NewKMSBackedSigner.
//
// This is typically called on startup to load signing keys from the database.
func LoadKMSBackedSigner(ctx context.Context, kp KeyProvider, region string, wrapped []byte) (*KMSBackedSigner, error) {
	// Unwrap the private key bytes.
	privDER, err := unwrapPrivateKey(ctx, kp, region, wrapped)
	if err != nil {
		return nil, fmt.Errorf("crypto: KMSBackedSigner: unwrap key: %w", err)
	}

	// Parse the PKCS#8 DER-encoded private key.
	privKey, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: KMSBackedSigner: parse private key: %w", err)
	}

	priv, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("crypto: KMSBackedSigner: expected ECDSA key, got %T", privKey)
	}

	// Verify it's a P-256 key.
	if priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("crypto: KMSBackedSigner: expected P-256 curve, got %s", priv.Curve.Params().Name)
	}

	return newKMSBackedSignerFromKey(priv), nil
}

// newKMSBackedSignerFromKey constructs a KMSBackedSigner from an existing key.
func newKMSBackedSignerFromKey(priv *ecdsa.PrivateKey) *KMSBackedSigner {
	var xBuf, yBuf [32]byte
	priv.X.FillBytes(xBuf[:])
	priv.Y.FillBytes(yBuf[:])
	x := base64.RawURLEncoding.EncodeToString(xBuf[:])
	y := base64.RawURLEncoding.EncodeToString(yBuf[:])
	kid := jwkThumbprint(x, y)
	return &KMSBackedSigner{
		priv: priv,
		kid:  kid,
		jwk: JWK{
			Kty: "EC",
			Crv: "P-256",
			Kid: kid,
			X:   x,
			Y:   y,
			Use: "sig",
			Alg: "ES256",
		},
	}
}

// Sign implements Signer. It computes SHA-256 of signingInput and returns the
// raw ES256 signature R‖S (each 32 bytes, left-padded).
func (s *KMSBackedSigner) Sign(signingInput []byte) ([]byte, error) {
	digest := sha256.Sum256(signingInput)
	r, sig, err := ecdsa.Sign(rand.Reader, s.priv, digest[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: KMSBackedSigner: ECDSA sign: %w", err)
	}
	var out [64]byte
	r.FillBytes(out[:32])
	sig.FillBytes(out[32:])
	return out[:], nil
}

// KeyID implements Signer.
func (s *KMSBackedSigner) KeyID() string { return s.kid }

// PublicJWK implements Signer.
func (s *KMSBackedSigner) PublicJWK() JWK { return s.jwk }

// String returns a human-readable identifier.
func (s *KMSBackedSigner) String() string { return "KMSBackedSigner" }

// --- Private key wrapping helpers ---

// wrappedKeyVersion is the version byte for the wrapped private key format.
// This allows future changes to the wrapping format.
const wrappedKeyVersion = 1

// wrapPrivateKey wraps a serialized private key using the KeyProvider.
// Format: version(1) | dekLen(2) | wrappedDEK | encryptedKey
//
// The private key is encrypted using a randomly generated DEK, and the DEK
// is wrapped using the KeyProvider (which uses KMS envelope encryption).
func wrapPrivateKey(ctx context.Context, kp KeyProvider, region string, privDER []byte) ([]byte, error) {
	// Generate a random DEK for encrypting the private key.
	dek, err := GenerateDEK()
	if err != nil {
		return nil, fmt.Errorf("generate DEK: %w", err)
	}

	// Encrypt the private key under the DEK.
	cipher := NewCipher()
	aad := []byte("harbor-signing-key-v1:" + region)
	encryptedKey, err := cipher.Encrypt(dek, privDER, aad)
	if err != nil {
		return nil, fmt.Errorf("encrypt private key: %w", err)
	}

	// Wrap the DEK using the KeyProvider (KMS envelope encryption).
	wrappedDEK, err := kp.WrapDEK(ctx, region, dek)
	if err != nil {
		return nil, fmt.Errorf("wrap DEK: %w", err)
	}

	// Build the output: version | len(wrappedDEK) as 2 bytes | wrappedDEK | encryptedKey
	output := make([]byte, 0, 3+len(wrappedDEK)+len(encryptedKey))
	output = append(output, wrappedKeyVersion)
	output = append(output, byte(len(wrappedDEK)>>8), byte(len(wrappedDEK)))
	output = append(output, wrappedDEK...)
	output = append(output, encryptedKey...)

	return output, nil
}

// unwrapPrivateKey unwraps a serialized private key using the KeyProvider.
func unwrapPrivateKey(ctx context.Context, kp KeyProvider, region string, wrapped []byte) ([]byte, error) {
	// Minimum length: version(1) + dekLen(2) + at least some DEK + some ciphertext
	if len(wrapped) < 4 {
		return nil, ErrDecryptFailed
	}

	// Check version.
	version := wrapped[0]
	if version != wrappedKeyVersion {
		return nil, ErrDecryptFailed
	}

	// Extract wrapped DEK length.
	dekLen := int(wrapped[1])<<8 | int(wrapped[2])
	if 3+dekLen >= len(wrapped) {
		return nil, ErrDecryptFailed
	}

	// Extract wrapped DEK and encrypted key.
	wrappedDEK := wrapped[3 : 3+dekLen]
	encryptedKey := wrapped[3+dekLen:]

	// Unwrap the DEK.
	dek, err := kp.UnwrapDEK(ctx, region, wrappedDEK)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	// Decrypt the private key.
	cipher := NewCipher()
	aad := []byte("harbor-signing-key-v1:" + region)
	privDER, err := cipher.Decrypt(dek, encryptedKey, aad)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	return privDER, nil
}
