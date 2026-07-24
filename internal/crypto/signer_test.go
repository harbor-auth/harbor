package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestSignerRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s := NewSignerFromKey(priv)
	input := []byte("header.payload")
	sig, err := s.Sign(input)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("sig len = %d, want 64", len(sig))
	}
	// Verify raw R‖S against the public key.
	digest := sha256.Sum256(input)
	r := new(big.Int).SetBytes(sig[:32])
	ss := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&priv.PublicKey, digest[:], r, ss) {
		t.Fatal("signature does not verify")
	}
}

func TestSignerKidStability(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s1 := NewSignerFromKey(priv)
	s2 := NewSignerFromKey(priv)
	if s1.KeyID() != s2.KeyID() {
		t.Fatalf("kid not stable: %s vs %s", s1.KeyID(), s2.KeyID())
	}
	if s1.KeyID() == "" {
		t.Fatal("kid is empty")
	}
}

func TestSignerRawSigFormat(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s := NewSignerFromKey(priv)
	for i := range 20 {
		sig, err := s.Sign([]byte{byte(i)})
		if err != nil {
			t.Fatalf("Sign[%d]: %v", i, err)
		}
		if len(sig) != 64 {
			t.Fatalf("Sign[%d]: len=%d, want 64", i, len(sig))
		}
	}
}

func TestJWKToPublicKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s := NewSignerFromKey(priv)
	jwk := s.PublicJWK()
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.Use != "sig" || jwk.Alg != "ES256" {
		t.Fatalf("unexpected JWK metadata: %+v", jwk)
	}
	pub, err := jwk.ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey: %v", err)
	}
	if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
		t.Fatal("reconstructed public key does not match")
	}
}

func TestJWKToPublicKeyOffCurve(t *testing.T) {
	// The all-zero point is not on P-256 and must be rejected.
	badJWK := JWK{
		Kty: "EC", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Y: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	if _, err := badJWK.ToPublicKey(); err == nil {
		t.Fatal("expected error for off-curve point, got nil")
	}
}

func TestJWKToPublicKeyBadBase64(t *testing.T) {
	badJWK := JWK{Kty: "EC", Crv: "P-256", X: "!!!not-base64!!!", Y: "also-bad"}
	if _, err := badJWK.ToPublicKey(); err == nil {
		t.Fatal("expected error for malformed base64, got nil")
	}
}

func TestLocalSignerString(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s := NewSignerFromKey(priv)
	if s.String() != "localSigner(DEV-ONLY)" {
		t.Fatalf("String() = %q, want %q", s.String(), "localSigner(DEV-ONLY)")
	}
}

func TestNewLocalSignerGeneratesUsableKey(t *testing.T) {
	s, err := NewLocalSigner()
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	sig, err := s.Sign([]byte("abc"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pub, err := s.PublicJWK().ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey: %v", err)
	}
	digest := sha256.Sum256([]byte("abc"))
	r := new(big.Int).SetBytes(sig[:32])
	ss := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, ss) {
		t.Fatal("NewLocalSigner signature does not verify against its own JWK")
	}
}
