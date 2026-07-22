package oidc

import (
	"context"
	"errors"
	"testing"
)

// TestVerifyRejectsCrossRegionIssuer proves region issuer/host coherence: a
// token minted on one region's issuer (https://eu.harbor.id) must NOT verify
// against another region's surface (https://us.harbor.id), even though the
// signature is valid. The same token verifies fine against its own region.
// (OpenSpec regional-data-residency-routing REQ-001, REQ-002.)
func TestVerifyRejectsCrossRegionIssuer(t *testing.T) {
	signer := newTestSigner(t)

	// Mint an access token whose iss claim is the EU region issuer.
	issuer := NewJWTIssuer(JWTIssuerConfig{Signer: signer, Now: fixedNow})
	p := testIssueParams()
	p.Issuer = "https://eu.harbor.id"
	tokens, err := issuer.Issue(context.Background(), p)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// A verifier pinned to the US region surface must reject the EU token.
	usVerifier, err := NewJWTVerifier(JWTVerifierConfig{
		Signer:         signer,
		ExpectedIssuer: "https://us.harbor.id",
		Now:            fixedNow,
	})
	if err != nil {
		t.Fatalf("NewJWTVerifier(us): %v", err)
	}
	if _, err := usVerifier.Verify(context.Background(), tokens.AccessToken); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("cross-region verify error = %v, want ErrIssuerMismatch", err)
	}

	// The same token verifies against its own EU region surface.
	euVerifier, err := NewJWTVerifier(JWTVerifierConfig{
		Signer:         signer,
		ExpectedIssuer: "https://eu.harbor.id",
		Now:            fixedNow,
	})
	if err != nil {
		t.Fatalf("NewJWTVerifier(eu): %v", err)
	}
	claims, err := euVerifier.Verify(context.Background(), tokens.AccessToken)
	if err != nil {
		t.Fatalf("same-region verify: unexpected error %v", err)
	}
	if claims.Issuer != "https://eu.harbor.id" {
		t.Fatalf("verified iss = %q, want https://eu.harbor.id", claims.Issuer)
	}
}

// TestVerifyIssuerCheckOptional confirms the coherence guard is opt-in: a
// verifier with no ExpectedIssuer does not enforce issuer matching, preserving
// backwards compatibility for callers that have not wired a region issuer.
func TestVerifyIssuerCheckOptional(t *testing.T) {
	signer := newTestSigner(t)
	issuer := NewJWTIssuer(JWTIssuerConfig{Signer: signer, Now: fixedNow})
	p := testIssueParams()
	p.Issuer = "https://eu.harbor.id"
	tokens, err := issuer.Issue(context.Background(), p)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	v, err := NewJWTVerifier(JWTVerifierConfig{Signer: signer, Now: fixedNow})
	if err != nil {
		t.Fatalf("NewJWTVerifier: %v", err)
	}
	if _, err := v.Verify(context.Background(), tokens.AccessToken); err != nil {
		t.Fatalf("verify without ExpectedIssuer: unexpected error %v", err)
	}
}
