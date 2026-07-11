package crypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
)

// Signer signs JWT signing inputs with an asymmetric key. The private key
// never leaves the Signer (or the regional HSM behind it). Sign hashes the
// input with SHA-256 internally (ES256 = ECDSA-P256-SHA256).
type Signer interface {
	// Sign signs signingInput (the JWT header.payload bytes) and returns the
	// raw ES256 signature: R‖S, each left-padded to 32 bytes (RFC 7518 §3.4).
	Sign(signingInput []byte) ([]byte, error)
	// KeyID returns the RFC 7638 JWK Thumbprint of the signing key.
	KeyID() string
	// PublicJWK returns the public key as a JWK for JWKS publication.
	PublicJWK() JWK
}

// JWK is a JSON Web Key (RFC 7517) for an EC P-256 signing key.
// X and Y are base64url-encoded, 32-byte-padded big-endian coordinates.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// ToPublicKey reconstructs the *ecdsa.PublicKey from the JWK. It returns an
// error if the coordinates are malformed or the point is not on P-256.
func (j JWK) ToPublicKey() (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("crypto: JWK x decode: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("crypto: JWK y decode: %w", err)
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	// Build the uncompressed SEC1 encoding manually (0x04 ∥ x_padded ∥ y_padded) and
	// validate via ecdh.P256().NewPublicKey — avoids the deprecated elliptic.Marshal/IsOnCurve APIs.
	if len(xBytes) > 32 || len(yBytes) > 32 {
		return nil, fmt.Errorf("crypto: JWK coordinate exceeds 32 bytes")
	}
	var xPad, yPad [32]byte
	copy(xPad[32-len(xBytes):], xBytes)
	copy(yPad[32-len(yBytes):], yBytes)
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	copy(uncompressed[1:33], xPad[:])
	copy(uncompressed[33:65], yPad[:])
	if _, err = ecdh.P256().NewPublicKey(uncompressed); err != nil {
		return nil, fmt.Errorf("crypto: JWK coordinates are not on P-256: %w", err)
	}
	return pub, nil
}

// LocalSigner is a dev-only in-process ES256 signer whose private key is held
// in memory. It self-identifies as DEV-ONLY at construction.
//
// SCAFFOLD — NOT FOR PRODUCTION. The production Signer wraps the regional HSM
// (docs/DESIGN.md §7.3): the private key never leaves the HSM boundary.
type LocalSigner struct {
	priv *ecdsa.PrivateKey
	jwk  JWK
	kid  string
}

// Compile-time proof that LocalSigner implements Signer.
var _ Signer = (*LocalSigner)(nil)

// NewLocalSigner generates a fresh P-256 key and returns a LocalSigner. It logs
// a prominent DEV-ONLY warning; String() returns "localSigner(DEV-ONLY)".
func NewLocalSigner() (*LocalSigner, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate P-256 key: %w", err)
	}
	s := newSignerFromKey(priv)
	slog.Warn("[HARBOR] DEV-ONLY localSigner: in-process ECDSA key, NOT backed by HSM — NEVER use in production",
		"kid", s.kid)
	return s, nil
}

// NewSignerFromKey wraps an existing *ecdsa.PrivateKey as a LocalSigner.
// Intended for tests and deterministic golden-vector construction.
func NewSignerFromKey(priv *ecdsa.PrivateKey) *LocalSigner {
	return newSignerFromKey(priv)
}

func newSignerFromKey(priv *ecdsa.PrivateKey) *LocalSigner {
	var xBuf, yBuf [32]byte
	priv.X.FillBytes(xBuf[:])
	priv.Y.FillBytes(yBuf[:])
	x := base64.RawURLEncoding.EncodeToString(xBuf[:])
	y := base64.RawURLEncoding.EncodeToString(yBuf[:])
	kid := jwkThumbprint(x, y)
	return &LocalSigner{
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

// jwkThumbprint computes the RFC 7638 JWK Thumbprint for a P-256 key. The
// required members in lexicographic order are: crv, kty, x, y (compact JSON,
// no extra whitespace).
func jwkThumbprint(x, y string) string {
	raw, err := json.Marshal(struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{Crv: "P-256", Kty: "EC", X: x, Y: y})
	if err != nil {
		// Marshaling a struct of plain strings is infallible; this branch is unreachable.
		panic(fmt.Sprintf("crypto: jwkThumbprint: unreachable marshal failure: %v", err))
	}
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Sign implements Signer. It computes SHA-256 of signingInput and returns the
// raw ES256 signature R‖S (each 32 bytes, left-padded via FillBytes).
func (s *LocalSigner) Sign(signingInput []byte) ([]byte, error) {
	digest := sha256.Sum256(signingInput)
	r, sig, err := ecdsa.Sign(rand.Reader, s.priv, digest[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: ECDSA sign: %w", err)
	}
	var out [64]byte
	r.FillBytes(out[:32])
	sig.FillBytes(out[32:])
	return out[:], nil
}

// KeyID implements Signer.
func (s *LocalSigner) KeyID() string { return s.kid }

// PublicJWK implements Signer.
func (s *LocalSigner) PublicJWK() JWK { return s.jwk }

// String returns the human-readable DEV-ONLY identifier.
func (s *LocalSigner) String() string { return "localSigner(DEV-ONLY)" }
