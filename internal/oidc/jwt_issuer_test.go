package oidc

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/harbor/harbor/internal/crypto"
)

// fixedNow is a deterministic clock for exp/iat assertions and golden vectors.
func fixedNow() time.Time {
	return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
}

// testIssueParams is a representative, PII-free issuance request.
func testIssueParams() IssueParams {
	return IssueParams{
		Issuer:   "https://eu.harbor.id",
		Subject:  "ppid-abc123",
		ClientID: "demo-client",
		Scope:    "openid profile",
		Nonce:    "n-0S6_WzA2Mj",
	}
}

func newTestSigner(t *testing.T) *crypto.LocalSigner {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return crypto.NewSignerFromKey(priv)
}

// verifyES256 verifies a compact JWT's ES256 signature against pub. It performs
// the exact offline verification an RP would: split, check 64-byte raw sig,
// SHA-256 the signing input, ecdsa.Verify with R=sig[:32], S=sig[32:].
func verifyES256(token string, pub *ecdsa.PublicKey) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
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

// errorSigner always fails, to exercise the Issue error path.
type errorSigner struct{ err error }

func (e errorSigner) Sign(_ []byte) ([]byte, error) { return nil, e.err }
func (e errorSigner) KeyID() string                 { return "test-kid" }
func (e errorSigner) PublicJWK() crypto.JWK         { return crypto.JWK{} }

// countingSigner fails after N successful calls, to exercise partial-issue paths.
type countingSigner struct {
	real      crypto.Signer
	failAfter int
	count     int
	err       error
}

func (c *countingSigner) Sign(data []byte) ([]byte, error) {
	c.count++
	if c.count > c.failAfter {
		return nil, c.err
	}
	return c.real.Sign(data)
}
func (c *countingSigner) KeyID() string         { return c.real.KeyID() }
func (c *countingSigner) PublicJWK() crypto.JWK { return c.real.PublicJWK() }

//harbor:invariant INV-JWT-SUB-IS-PPID
func TestJWTIssuerSubIsPPID(t *testing.T) {
	signer := newTestSigner(t)
	iss := NewJWTIssuer(JWTIssuerConfig{Signer: signer, Now: fixedNow})
	p := testIssueParams()
	tokens, err := iss.Issue(context.Background(), p)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	for name, tok := range map[string]string{"id": tokens.IDToken, "access": tokens.AccessToken} {
		_, payload, _, err := parseCompactJWT(tok)
		if err != nil {
			t.Fatalf("%s parse: %v", name, err)
		}
		var claims map[string]any
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatalf("%s unmarshal: %v", name, err)
		}
		if claims["sub"] != p.Subject {
			t.Fatalf("%s sub = %v, want PPID %q", name, claims["sub"], p.Subject)
		}
	}
}

//harbor:invariant INV-JWT-NO-PII
func TestJWTIssuerNoPII(t *testing.T) {
	signer := newTestSigner(t)
	iss := NewJWTIssuer(JWTIssuerConfig{Signer: signer, Now: fixedNow})
	tokens, err := iss.Issue(context.Background(), testIssueParams())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	allowedID := map[string]bool{"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "nonce": true}
	allowedAccess := map[string]bool{"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "scope": true, "jti": true}
	forbidden := []string{"email", "name", "given_name", "family_name", "phone_number", "address"}

	check := func(name, tok string, allowed map[string]bool) {
		_, payload, _, err := parseCompactJWT(tok)
		if err != nil {
			t.Fatalf("%s parse: %v", name, err)
		}
		var claims map[string]any
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatalf("%s unmarshal: %v", name, err)
		}
		for k := range claims {
			if !allowed[k] {
				t.Fatalf("%s token has unexpected claim %q (possible PII leak)", name, k)
			}
		}
		for _, f := range forbidden {
			if _, ok := claims[f]; ok {
				t.Fatalf("%s token contains forbidden PII claim %q", name, f)
			}
		}
	}
	check("id", tokens.IDToken, allowedID)
	check("access", tokens.AccessToken, allowedAccess)
}

//harbor:invariant INV-JWKS-KID-MATCH
func TestJWTIssuerKidMatchesJWKS(t *testing.T) {
	signer := newTestSigner(t)
	iss := NewJWTIssuer(JWTIssuerConfig{Signer: signer, Now: fixedNow})
	tokens, err := iss.Issue(context.Background(), testIssueParams())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	jwks := BuildJWKS([]crypto.Signer{signer})

	for name, tok := range map[string]string{"id": tokens.IDToken, "access": tokens.AccessToken} {
		headerBytes, _, _, err := parseCompactJWT(tok)
		if err != nil {
			t.Fatalf("%s parse: %v", name, err)
		}
		var hdr jwtHeader
		if err := json.Unmarshal(headerBytes, &hdr); err != nil {
			t.Fatalf("%s header unmarshal: %v", name, err)
		}
		// The kid must resolve to exactly one JWKS key.
		var matched *ecdsa.PublicKey
		count := 0
		for _, k := range jwks.Keys {
			if k.Kid == hdr.Kid {
				count++
				pub, err := crypto.JWK{Kty: k.Kty, Crv: k.Crv, Kid: k.Kid, X: k.X, Y: k.Y, Use: k.Use, Alg: k.Alg}.ToPublicKey()
				if err != nil {
					t.Fatalf("%s JWKS key ToPublicKey: %v", name, err)
				}
				matched = pub
			}
		}
		if count != 1 {
			t.Fatalf("%s kid %q resolved to %d JWKS keys, want exactly 1", name, hdr.Kid, count)
		}
		if !verifyES256(tok, matched) {
			t.Fatalf("%s token does not verify against its JWKS key", name)
		}
	}
}

func TestJWTIssuerVerifyRoundTrip(t *testing.T) {
	signer := newTestSigner(t)
	iss := NewJWTIssuer(JWTIssuerConfig{Signer: signer, Now: fixedNow})
	tokens, err := iss.Issue(context.Background(), testIssueParams())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pub, err := signer.PublicJWK().ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey: %v", err)
	}
	if !verifyES256(tokens.IDToken, pub) {
		t.Fatal("ID token failed offline verification")
	}
	if !verifyES256(tokens.AccessToken, pub) {
		t.Fatal("access token failed offline verification")
	}
}

func TestJWTIssuerShortTTL(t *testing.T) {
	signer := newTestSigner(t)
	iss := NewJWTIssuer(JWTIssuerConfig{Signer: signer, Now: fixedNow})
	tokens, err := iss.Issue(context.Background(), testIssueParams())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tokens.ExpiresIn != accessTokenTTLSeconds {
		t.Fatalf("ExpiresIn = %d, want %d", tokens.ExpiresIn, accessTokenTTLSeconds)
	}
	_, payload, _, err := parseCompactJWT(tokens.AccessToken)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var claims accessTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if claims.Expiry-claims.IssuedAt != accessTokenTTLSeconds {
		t.Fatalf("exp-iat = %d, want %d", claims.Expiry-claims.IssuedAt, accessTokenTTLSeconds)
	}
}

func TestJWTIssuerExpiredTokenDetectable(t *testing.T) {
	signer := newTestSigner(t)
	// Issue in the distant past so exp is well before "now".
	past := func() time.Time { return time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC) }
	iss := NewJWTIssuer(JWTIssuerConfig{Signer: signer, Now: past})
	tokens, err := iss.Issue(context.Background(), testIssueParams())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, payload, _, err := parseCompactJWT(tokens.IDToken)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var claims idTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// An RP checks exp against the real wall clock; a token minted in 2000 is
	// long expired now.
	if time.Now().Unix() <= claims.Expiry {
		t.Fatalf("expected exp %d to be in the past", claims.Expiry)
	}
}

func TestJWTIssuerTamperedPayloadRejected(t *testing.T) {
	signer := newTestSigner(t)
	iss := NewJWTIssuer(JWTIssuerConfig{Signer: signer, Now: fixedNow})
	tokens, err := iss.Issue(context.Background(), testIssueParams())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pub, err := signer.PublicJWK().ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey: %v", err)
	}
	parts := strings.Split(tokens.IDToken, ".")
	// Tamper the payload: decode, mutate sub, re-encode; signature no longer matches.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	claims["sub"] = "attacker"
	tampered, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}
	badToken := parts[0] + "." + base64.RawURLEncoding.EncodeToString(tampered) + "." + parts[2]
	if verifyES256(badToken, pub) {
		t.Fatal("tampered token verified — signature check is broken")
	}
}

func TestJWTIssuerTamperedSignatureRejected(t *testing.T) {
	signer := newTestSigner(t)
	iss := NewJWTIssuer(JWTIssuerConfig{Signer: signer, Now: fixedNow})
	tokens, err := iss.Issue(context.Background(), testIssueParams())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pub, err := signer.PublicJWK().ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey: %v", err)
	}
	parts := strings.Split(tokens.IDToken, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sig[0] ^= 0xFF // flip a byte
	badToken := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
	if verifyES256(badToken, pub) {
		t.Fatal("token with flipped signature byte verified")
	}
}

func TestJWTIssuerSignerError(t *testing.T) {
	sentinel := errors.New("signer boom")
	iss := NewJWTIssuer(JWTIssuerConfig{Signer: errorSigner{err: sentinel}, Now: fixedNow})
	_, err := iss.Issue(context.Background(), testIssueParams())
	if err == nil {
		t.Fatal("expected Issue to fail when signer errors")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel error, got %v", err)
	}
}

// TestJWTIssuerAccessTokenSignerError verifies that if the ID token is signed
// successfully but the access token signing fails, Issue returns an error.
func TestJWTIssuerAccessTokenSignerError(t *testing.T) {
	sentinel := errors.New("access token signer boom")
	realSigner := newTestSigner(t)
	counting := &countingSigner{
		real:      realSigner,
		failAfter: 1, // ID token succeeds (1 sign), access token fails (2nd sign)
		err:       sentinel,
	}
	iss := NewJWTIssuer(JWTIssuerConfig{Signer: counting, Now: fixedNow})
	_, err := iss.Issue(context.Background(), testIssueParams())
	if err == nil {
		t.Fatal("expected Issue to fail when access token signer errors")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel error, got %v", err)
	}
	if !strings.Contains(err.Error(), "access token") {
		t.Fatalf("error should mention 'access token', got: %v", err)
	}
}

// TestJWTIssuerIDTokenSignerError verifies error message mentions ID token.
func TestJWTIssuerIDTokenSignerError(t *testing.T) {
	sentinel := errors.New("id token signer boom")
	iss := NewJWTIssuer(JWTIssuerConfig{Signer: errorSigner{err: sentinel}, Now: fixedNow})
	_, err := iss.Issue(context.Background(), testIssueParams())
	if err == nil {
		t.Fatal("expected Issue to fail when ID token signer errors")
	}
	if !strings.Contains(err.Error(), "ID token") {
		t.Fatalf("error should mention 'ID token', got: %v", err)
	}
}

func TestJWTIssuerNonceOmittedWhenEmpty(t *testing.T) {
	signer := newTestSigner(t)
	iss := NewJWTIssuer(JWTIssuerConfig{Signer: signer, Now: fixedNow})
	p := testIssueParams()
	p.Nonce = ""
	tokens, err := iss.Issue(context.Background(), p)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, payload, _, err := parseCompactJWT(tokens.IDToken)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := claims["nonce"]; ok {
		t.Fatal("empty nonce should be omitted from ID token claims")
	}
}

// fixedGoldenKey returns the deterministic P-256 key used for golden vectors,
// derived from the NIST test scalar in jwt_vectors.json.
func fixedGoldenKey(t *testing.T, dHex string) *ecdsa.PrivateKey {
	t.Helper()
	d, ok := new(big.Int).SetString(dHex, 16)
	if !ok {
		t.Fatalf("invalid fixed key hex")
	}
	// Derive the public point via ecdh (avoids deprecated elliptic.ScalarBaseMult since Go 1.21).
	dBytes := make([]byte, 32)
	d.FillBytes(dBytes)
	ecdhPriv, err := ecdh.P256().NewPrivateKey(dBytes)
	if err != nil {
		t.Fatalf("ecdh NewPrivateKey: %v", err)
	}
	pubBytes := ecdhPriv.PublicKey().Bytes() // uncompressed SEC1: 0x04 || x || y
	priv := new(ecdsa.PrivateKey)
	priv.Curve = elliptic.P256()
	priv.D = d
	priv.X = new(big.Int).SetBytes(pubBytes[1:33])
	priv.Y = new(big.Int).SetBytes(pubBytes[33:65])
	return priv
}

type jwtGoldenVectors struct {
	FixedKeyDHex        string `json:"fixed_key_d_hex"`
	ExpectedKid         string `json:"expected_kid"`
	ExpectedX           string `json:"expected_x"`
	ExpectedY           string `json:"expected_y"`
	IDTokenHeaderB64    string `json:"id_token_header_b64"`
	IDTokenPayloadB64   string `json:"id_token_payload_b64"`
	FrozenSignedIDToken string `json:"frozen_signed_id_token"`
}

// TestJWTGoldenVectors freezes the deterministic parts of issuance (kid, JWK
// x/y, ID-token header + payload base64) by byte-equality, and verifies a
// pre-signed frozen JWT against the fixed public key. It never re-signs the
// frozen token (ES256 signatures are non-deterministic), so the frozen token
// must be produced once and pasted into testdata/jwt_vectors.json.
//
//harbor:invariant INV-JWKS-KID-MATCH
func TestJWTGoldenVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/jwt_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v jwtGoldenVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal vectors: %v", err)
	}

	priv := fixedGoldenKey(t, v.FixedKeyDHex)
	signer := crypto.NewSignerFromKey(priv)
	jwk := signer.PublicJWK()

	// Build the deterministic ID-token header + payload for the fixed inputs.
	iss := NewJWTIssuer(JWTIssuerConfig{Signer: signer, Now: fixedNow})
	tokens, err := iss.Issue(context.Background(), testIssueParams())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	idParts := strings.Split(tokens.IDToken, ".")

	computed := jwtGoldenVectors{
		FixedKeyDHex:      v.FixedKeyDHex,
		ExpectedKid:       jwk.Kid,
		ExpectedX:         jwk.X,
		ExpectedY:         jwk.Y,
		IDTokenHeaderB64:  idParts[0],
		IDTokenPayloadB64: idParts[1],
	}

	// Any <FILL> sentinel means the vectors have not been frozen yet: print the
	// computed deterministic values plus a freshly-signed frozen token so they
	// can be pasted in, then fail.
	if strings.Contains(string(raw), "<FILL>") {
		t.Logf("freeze these into testdata/jwt_vectors.json:")
		t.Logf("  expected_kid:        %s", computed.ExpectedKid)
		t.Logf("  expected_x:          %s", computed.ExpectedX)
		t.Logf("  expected_y:          %s", computed.ExpectedY)
		t.Logf("  id_token_header_b64: %s", computed.IDTokenHeaderB64)
		t.Logf("  id_token_payload_b64:%s", computed.IDTokenPayloadB64)
		t.Logf("  frozen_signed_id_token: %s", tokens.IDToken)
		t.Fatal("jwt_vectors.json contains <FILL> — freeze the printed values above")
	}

	// Byte-equality on all deterministic parts.
	if jwk.Kid != v.ExpectedKid {
		t.Fatalf("kid = %s, want frozen %s", jwk.Kid, v.ExpectedKid)
	}
	if jwk.X != v.ExpectedX || jwk.Y != v.ExpectedY {
		t.Fatalf("JWK x/y drift: got (%s,%s), want (%s,%s)", jwk.X, jwk.Y, v.ExpectedX, v.ExpectedY)
	}
	if idParts[0] != v.IDTokenHeaderB64 {
		t.Fatalf("id header b64 = %s, want frozen %s", idParts[0], v.IDTokenHeaderB64)
	}
	if idParts[1] != v.IDTokenPayloadB64 {
		t.Fatalf("id payload b64 = %s, want frozen %s", idParts[1], v.IDTokenPayloadB64)
	}

	// Verify the FROZEN pre-signed token (never re-sign): it must verify, and
	// its header/payload must byte-match the frozen deterministic parts.
	frozenParts := strings.Split(v.FrozenSignedIDToken, ".")
	if len(frozenParts) != 3 {
		t.Fatalf("frozen token malformed")
	}
	if frozenParts[0] != v.IDTokenHeaderB64 || frozenParts[1] != v.IDTokenPayloadB64 {
		t.Fatalf("frozen token header/payload diverges from frozen deterministic parts")
	}
	pub, err := jwk.ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey: %v", err)
	}
	if !verifyES256(v.FrozenSignedIDToken, pub) {
		t.Fatal("frozen pre-signed token failed verification against fixed public key")
	}
}
