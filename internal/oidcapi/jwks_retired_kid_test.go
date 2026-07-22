package oidcapi

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/openapi"
)

// Integration test for the signing-key-rotation verification invariant
// (docs/DESIGN.md §7.3, §3.5.4): once a key is retired and removed from
// /jwks.json, an RP performing offline verification can no longer resolve its
// kid to a public key, so any token signed by that retired key MUST fail
// verification. Meanwhile tokens signed with the current active key — whose kid
// is still published — verify successfully.
//
// These tests drive the real serving path: MultiKeyProvider models the rotation
// lifecycle (overlap → retire), the resulting live signers are served through
// the oidcapi.Server's GET /jwks.json, and verification mimics exactly what an
// RP does: read the token's kid, look it up in the served JWKS, and ES256-verify
// against the matching public key.

// signToken mints a minimal compact ES256 JWT signed by the given signer. The
// JOSE header carries the signer's kid so an RP can resolve the verifying key
// from JWKS.
func signToken(t *testing.T, signer crypto.Signer) string {
	t.Helper()
	headerJSON, err := json.Marshal(map[string]string{
		"alg": "ES256",
		"typ": "JWT",
		"kid": signer.KeyID(),
	})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadJSON, err := json.Marshal(map[string]any{
		"iss": "https://eu.harbor.id",
		"sub": "ppid-abc123",
		"aud": "demo-client",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig, err := signer.Sign([]byte(signingInput))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// fetchJWKS builds a Server serving the given live signers and returns the
// decoded JWKS document served at GET /jwks.json.
func fetchJWKS(t *testing.T, signers ...crypto.Signer) openapi.JWKSet {
	t.Helper()
	srv := New(Config{Issuer: "https://eu.harbor.id", Signers: signers})

	req := httptest.NewRequest(http.MethodGet, "/jwks.json", nil)
	rec := httptest.NewRecorder()
	srv.GetJwks(rec, req)

	res := rec.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /jwks.json = %d, want 200", res.StatusCode)
	}
	var set openapi.JWKSet
	if err := json.NewDecoder(res.Body).Decode(&set); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	return set
}

// verifyTokenAgainstJWKS performs RP-style offline verification: it reads the
// token's kid, resolves it to a public key in the served JWKS, and ES256-verifies
// the signature. It returns false if the kid is absent from JWKS (retired key),
// mirroring how a real RP rejects tokens it cannot resolve a key for.
func verifyTokenAgainstJWKS(t *testing.T, token string, jwks openapi.JWKSet) bool {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var hdr struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return false
	}

	// Resolve the token's kid to exactly one JWKS key. Absent kid → retired key
	// → cannot verify.
	var pub *ecdsa.PublicKey
	for _, k := range jwks.Keys {
		if k.Kid != hdr.Kid {
			continue
		}
		p, err := crypto.JWK{Kty: k.Kty, Crv: k.Crv, Kid: k.Kid, X: k.X, Y: k.Y, Use: k.Use, Alg: k.Alg}.ToPublicKey()
		if err != nil {
			t.Fatalf("JWKS key ToPublicKey: %v", err)
		}
		pub = p
		break
	}
	if pub == nil {
		return false
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, digest[:], r, s)
}

// TestTokenWithRetiredKidRejected verifies that a token signed with a key that
// has been retired (removed from JWKS) fails verification, while a token signed
// with the new active key verifies successfully.
func TestTokenWithRetiredKidRejected(t *testing.T) {
	oldSigner := newTestSigner(t)
	newSigner := newTestSigner(t)
	if oldSigner.KeyID() == newSigner.KeyID() {
		t.Fatal("expected distinct kids for two freshly generated signers")
	}

	// A token minted by the old key before its retirement.
	oldToken := signToken(t, oldSigner)

	// Rotate to the new key, then retire the old one (remove it from the live
	// set once its overlap window elapses) so JWKS publishes only the new key.
	provider, err := crypto.NewMultiKeyProvider(newSigner, oldSigner)
	if err != nil {
		t.Fatalf("NewMultiKeyProvider: %v", err)
	}
	if err := provider.Remove(oldSigner.KeyID()); err != nil {
		t.Fatalf("Remove old signer: %v", err)
	}
	jwks := fetchJWKS(t, provider.AllSigners()...)

	// The old kid is gone from JWKS → the retired-key token must NOT verify.
	if verifyTokenAgainstJWKS(t, oldToken, jwks) {
		t.Fatal("token signed with a retired kid verified — it must be rejected once the kid leaves JWKS")
	}

	// A fresh token from the new active key still verifies.
	newToken := signToken(t, newSigner)
	if !verifyTokenAgainstJWKS(t, newToken, jwks) {
		t.Fatal("token signed with the active kid failed verification")
	}
}

// TestTokenWithOldKidVerifiesDuringOverlap is the contrast case to retirement:
// while the old key is still within its overlap window (present in JWKS), a
// token signed with it MUST still verify. This guards against retiring keys too
// eagerly and breaking in-flight tokens.
func TestTokenWithOldKidVerifiesDuringOverlap(t *testing.T) {
	oldSigner := newTestSigner(t)
	newSigner := newTestSigner(t)

	oldToken := signToken(t, oldSigner)

	// Overlap: new key active, old key kept live in JWKS.
	provider, err := crypto.NewMultiKeyProvider(newSigner, oldSigner)
	if err != nil {
		t.Fatalf("NewMultiKeyProvider: %v", err)
	}
	jwks := fetchJWKS(t, provider.AllSigners()...)

	if !verifyTokenAgainstJWKS(t, oldToken, jwks) {
		t.Fatal("token signed with the old kid failed verification during the overlap window")
	}
}
