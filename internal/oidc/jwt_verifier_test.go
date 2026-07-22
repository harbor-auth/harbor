package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/crypto"
)

// newTestVerifier creates a JWTVerifier with a test signer for unit tests.
func newTestVerifier(t *testing.T, opts ...func(*JWTVerifierConfig)) (*JWTVerifier, crypto.Signer) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := crypto.NewSignerFromKey(priv)
	cfg := JWTVerifierConfig{
		Signer: signer,
		Now:    fixedNow,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	verifier, err := NewJWTVerifier(cfg)
	if err != nil {
		t.Fatalf("NewJWTVerifier: %v", err)
	}
	return verifier, signer
}

// issueTestToken issues a token with the given signer for testing.
func issueTestToken(t *testing.T, signer crypto.Signer, now func() time.Time) IssuedTokens {
	t.Helper()
	iss := NewJWTIssuer(JWTIssuerConfig{Signer: signer, Now: now})
	tokens, err := iss.Issue(context.Background(), testIssueParams())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tokens
}

func TestJWTVerifierVerifyValidToken(t *testing.T) {
	verifier, signer := newTestVerifier(t)
	tokens := issueTestToken(t, signer, fixedNow)

	claims, err := verifier.Verify(context.Background(), tokens.AccessToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != testIssueParams().Subject {
		t.Errorf("Subject = %q, want %q", claims.Subject, testIssueParams().Subject)
	}
}

func TestJWTVerifierVerifyExpiredToken(t *testing.T) {
	// Issue token in the past so it's expired by "now"
	past := func() time.Time { return time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC) }
	verifier, signer := newTestVerifier(t, func(cfg *JWTVerifierConfig) {
		cfg.Now = fixedNow // verifier uses current time
	})
	tokens := issueTestToken(t, signer, past)

	_, err := verifier.Verify(context.Background(), tokens.AccessToken)
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("Verify expired token: got %v, want ErrTokenExpired", err)
	}
}

func TestJWTVerifierVerifyInvalidSignature(t *testing.T) {
	verifier, signer := newTestVerifier(t)
	tokens := issueTestToken(t, signer, fixedNow)

	// Tamper with the signature
	parts := strings.Split(tokens.AccessToken, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sig[0] ^= 0xFF // flip a byte
	tamperedToken := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)

	_, verifyErr := verifier.Verify(context.Background(), tamperedToken)
	if !errors.Is(verifyErr, ErrTokenInvalid) {
		t.Fatalf("Verify tampered token: got %v, want ErrTokenInvalid", verifyErr)
	}
}

func TestJWTVerifierVerifyIssuerMismatch(t *testing.T) {
	verifier, signer := newTestVerifier(t, func(cfg *JWTVerifierConfig) {
		cfg.ExpectedIssuer = "https://different-issuer.example.com"
	})
	tokens := issueTestToken(t, signer, fixedNow)

	_, err := verifier.Verify(context.Background(), tokens.AccessToken)
	if !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("Verify issuer mismatch: got %v, want ErrIssuerMismatch", err)
	}
}

// --- VerifySignatureOnly tests for RP-Initiated Logout ---

func TestJWTVerifierVerifySignatureOnlyValidToken(t *testing.T) {
	verifier, signer := newTestVerifier(t)
	tokens := issueTestToken(t, signer, fixedNow)

	claims, err := verifier.VerifySignatureOnly(context.Background(), tokens.IDToken)
	if err != nil {
		t.Fatalf("VerifySignatureOnly: %v", err)
	}
	if claims.Subject != testIssueParams().Subject {
		t.Errorf("Subject = %q, want %q", claims.Subject, testIssueParams().Subject)
	}
}

// TestJWTVerifierVerifySignatureOnlyAcceptsExpiredToken verifies that
// VerifySignatureOnly accepts expired tokens — this is the key behavior for
// RP-Initiated Logout where users may log out with expired id_token_hint.
func TestJWTVerifierVerifySignatureOnlyAcceptsExpiredToken(t *testing.T) {
	// Issue token in the past so it's expired by "now"
	past := func() time.Time { return time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC) }
	verifier, signer := newTestVerifier(t, func(cfg *JWTVerifierConfig) {
		cfg.Now = fixedNow // verifier uses current time
	})
	tokens := issueTestToken(t, signer, past)

	// VerifySignatureOnly should succeed even with expired token
	claims, err := verifier.VerifySignatureOnly(context.Background(), tokens.IDToken)
	if err != nil {
		t.Fatalf("VerifySignatureOnly on expired token: %v (expected success)", err)
	}
	if claims.Subject != testIssueParams().Subject {
		t.Errorf("Subject = %q, want %q", claims.Subject, testIssueParams().Subject)
	}
	// Verify the token is indeed expired (exp is in the past)
	if claims.Expiry.After(fixedNow()) {
		t.Error("expected token to be expired for this test")
	}
}

func TestJWTVerifierVerifySignatureOnlyRejectsInvalidSignature(t *testing.T) {
	verifier, signer := newTestVerifier(t)
	tokens := issueTestToken(t, signer, fixedNow)

	// Tamper with the signature
	parts := strings.Split(tokens.IDToken, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sig[0] ^= 0xFF // flip a byte
	tamperedToken := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)

	_, verifyErr := verifier.VerifySignatureOnly(context.Background(), tamperedToken)
	if !errors.Is(verifyErr, ErrTokenInvalid) {
		t.Fatalf("VerifySignatureOnly tampered token: got %v, want ErrTokenInvalid", verifyErr)
	}
}

func TestJWTVerifierVerifySignatureOnlyRejectsTamperedPayload(t *testing.T) {
	verifier, signer := newTestVerifier(t)
	tokens := issueTestToken(t, signer, fixedNow)

	// Tamper the payload: decode, mutate sub, re-encode
	parts := strings.Split(tokens.IDToken, ".")
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
	tamperedToken := parts[0] + "." + base64.RawURLEncoding.EncodeToString(tampered) + "." + parts[2]

	_, verifyErr := verifier.VerifySignatureOnly(context.Background(), tamperedToken)
	if !errors.Is(verifyErr, ErrTokenInvalid) {
		t.Fatalf("VerifySignatureOnly tampered payload: got %v, want ErrTokenInvalid", verifyErr)
	}
}

func TestJWTVerifierVerifySignatureOnlyRejectsIssuerMismatch(t *testing.T) {
	verifier, signer := newTestVerifier(t, func(cfg *JWTVerifierConfig) {
		cfg.ExpectedIssuer = "https://different-issuer.example.com"
	})
	tokens := issueTestToken(t, signer, fixedNow)

	_, err := verifier.VerifySignatureOnly(context.Background(), tokens.IDToken)
	if !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("VerifySignatureOnly issuer mismatch: got %v, want ErrIssuerMismatch", err)
	}
}

func TestJWTVerifierVerifySignatureOnlyMalformedToken(t *testing.T) {
	verifier, _ := newTestVerifier(t)

	testCases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no dots", "notavalidtoken"},
		{"one dot", "header.payload"},
		{"invalid base64", "!!!.!!!.!!!"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifier.VerifySignatureOnly(context.Background(), tc.token)
			if !errors.Is(err, ErrTokenInvalid) {
				t.Errorf("VerifySignatureOnly(%q): got %v, want ErrTokenInvalid", tc.token, err)
			}
		})
	}
}

func TestJWTVerifierVerifySignatureOnlyWrongAlgorithm(t *testing.T) {
	verifier, signer := newTestVerifier(t)
	tokens := issueTestToken(t, signer, fixedNow)

	// Replace header with a different algorithm
	badHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	parts := strings.Split(tokens.IDToken, ".")
	tamperedToken := badHeader + "." + parts[1] + "." + parts[2]

	_, err := verifier.VerifySignatureOnly(context.Background(), tamperedToken)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("VerifySignatureOnly wrong algorithm: got %v, want ErrTokenInvalid", err)
	}
}

func TestJWTVerifierNoPublicKey(t *testing.T) {
	verifier, err := NewJWTVerifier(JWTVerifierConfig{
		Signer: nil, // no signer = no public key
		Now:    fixedNow,
	})
	if err != nil {
		t.Fatalf("NewJWTVerifier: %v", err)
	}

	// Create a valid-looking token (we just need something to parse)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
	sig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	token := header + "." + payload + "." + sig

	_, err = verifier.VerifySignatureOnly(context.Background(), token)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("VerifySignatureOnly without public key: got %v, want ErrTokenInvalid", err)
	}
}
