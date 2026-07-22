package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/crypto"
)

// testIntrospector creates an Introspector with the given signer and options.
func testIntrospector(t *testing.T, signer crypto.Signer, opts ...func(*IntrospectConfig)) *Introspector {
	t.Helper()
	cfg := IntrospectConfig{
		Signers: []crypto.Signer{signer},
		Now:     fixedNow,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return NewIntrospector(cfg)
}

// issueTestAccessToken creates a signed access token for testing.
func issueTestAccessToken(t *testing.T, signer crypto.Signer, clientID string) string {
	t.Helper()
	iss := NewJWTIssuer(JWTIssuerConfig{Signer: signer, Now: fixedNow})
	tokens, err := iss.Issue(context.Background(), IssueParams{
		Issuer:   "https://eu.harbor.id",
		Subject:  "ppid-test-user",
		ClientID: clientID,
		Scope:    "openid profile",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tokens.AccessToken
}

// TestIntrospectValidToken verifies that a valid token returns active + claims.
func TestIntrospectValidToken(t *testing.T) {
	signer := newTestSigner(t)
	intro := testIntrospector(t, signer)
	token := issueTestAccessToken(t, signer, "demo-client")

	resp := intro.Introspect(context.Background(), IntrospectRequest{
		Token:    token,
		ClientID: "demo-client",
	})

	if !resp.Active {
		t.Fatal("expected active=true for valid token")
	}
	if resp.Sub != "ppid-test-user" {
		t.Fatalf("sub = %q, want %q", resp.Sub, "ppid-test-user")
	}
	if resp.Scope != "openid profile" {
		t.Fatalf("scope = %q, want %q", resp.Scope, "openid profile")
	}
	if resp.ClientID != "demo-client" {
		t.Fatalf("client_id = %q, want %q", resp.ClientID, "demo-client")
	}
	if resp.TokenType != "Bearer" {
		t.Fatalf("token_type = %q, want %q", resp.TokenType, "Bearer")
	}
	if resp.Jti == "" {
		t.Fatal("expected jti to be present")
	}
}

// TestIntrospectInvalidSignature verifies that a token with invalid signature returns inactive.
func TestIntrospectInvalidSignature(t *testing.T) {
	signer1 := newTestSigner(t)
	signer2 := newTestSigner(t) // different key

	// Issue token with signer1
	token := issueTestAccessToken(t, signer1, "demo-client")

	// Introspect with signer2 (different key)
	intro := testIntrospector(t, signer2)
	resp := intro.Introspect(context.Background(), IntrospectRequest{
		Token:    token,
		ClientID: "demo-client",
	})

	if resp.Active {
		t.Fatal("expected active=false for token signed with different key")
	}
	// Verify no claims are leaked
	if resp.Sub != "" || resp.Scope != "" || resp.ClientID != "" {
		t.Fatal("expected no claims in inactive response")
	}
}

// TestIntrospectExpiredToken verifies that an expired token returns inactive.
func TestIntrospectExpiredToken(t *testing.T) {
	signer := newTestSigner(t)

	// Issue token in the past
	pastTime := func() time.Time { return time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC) }
	iss := NewJWTIssuer(JWTIssuerConfig{Signer: signer, Now: pastTime})
	tokens, err := iss.Issue(context.Background(), IssueParams{
		Issuer:   "https://eu.harbor.id",
		Subject:  "ppid-test-user",
		ClientID: "demo-client",
		Scope:    "openid",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Introspect with current time (token is expired)
	intro := testIntrospector(t, signer, func(cfg *IntrospectConfig) {
		cfg.Now = time.Now // use real time
	})
	resp := intro.Introspect(context.Background(), IntrospectRequest{
		Token:    tokens.AccessToken,
		ClientID: "demo-client",
	})

	if resp.Active {
		t.Fatal("expected active=false for expired token")
	}
}

// TestIntrospectRevokedTokenBloomAndDB verifies that a revoked token (bloom + DB confirm) returns inactive.
func TestIntrospectRevokedTokenBloomAndDB(t *testing.T) {
	signer := newTestSigner(t)
	token := issueTestAccessToken(t, signer, "demo-client")

	// Extract JTI from token
	_, payload, _, err := parseCompactJWT(token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := unmarshalJSON(payload, &claims); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Create filter with the JTI
	filter := NewInMemoryRevocationFilter()
	filter.Add(claims.JTI)

	// Create DB checker that confirms revocation
	checker := &mockRevokedJTIChecker{revoked: map[string]bool{claims.JTI: true}}

	intro := testIntrospector(t, signer, func(cfg *IntrospectConfig) {
		cfg.Filter = filter
		cfg.RevokedChecker = checker
	})

	resp := intro.Introspect(context.Background(), IntrospectRequest{
		Token:    token,
		ClientID: "demo-client",
	})

	if resp.Active {
		t.Fatal("expected active=false for revoked token")
	}
}

// TestIntrospectBloomFalsePositive verifies that a bloom false positive returns active.
func TestIntrospectBloomFalsePositive(t *testing.T) {
	signer := newTestSigner(t)
	token := issueTestAccessToken(t, signer, "demo-client")

	// Extract JTI from token
	_, payload, _, err := parseCompactJWT(token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := unmarshalJSON(payload, &claims); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Create filter with the JTI (simulating a bloom hit)
	filter := NewInMemoryRevocationFilter()
	filter.Add(claims.JTI)

	// Create DB checker that says NOT revoked (false positive)
	checker := &mockRevokedJTIChecker{revoked: map[string]bool{}}

	intro := testIntrospector(t, signer, func(cfg *IntrospectConfig) {
		cfg.Filter = filter
		cfg.RevokedChecker = checker
	})

	resp := intro.Introspect(context.Background(), IntrospectRequest{
		Token:    token,
		ClientID: "demo-client",
	})

	if !resp.Active {
		t.Fatal("expected active=true for bloom false positive (DB says not revoked)")
	}
}

// TestIntrospectCrossClientAudMismatch verifies that aud mismatch returns inactive.
func TestIntrospectCrossClientAudMismatch(t *testing.T) {
	signer := newTestSigner(t)
	// Issue token for "client-a"
	token := issueTestAccessToken(t, signer, "client-a")

	intro := testIntrospector(t, signer)

	// Introspect as "client-b" (different client)
	resp := intro.Introspect(context.Background(), IntrospectRequest{
		Token:    token,
		ClientID: "client-b",
	})

	if resp.Active {
		t.Fatal("expected active=false for cross-client aud mismatch")
	}
}

// TestIntrospectAdminBypassesAudCheck verifies that admin can introspect any token.
func TestIntrospectAdminBypassesAudCheck(t *testing.T) {
	signer := newTestSigner(t)
	// Issue token for "client-a"
	token := issueTestAccessToken(t, signer, "client-a")

	intro := testIntrospector(t, signer)

	// Introspect as admin (different client but IsAdmin=true)
	resp := intro.Introspect(context.Background(), IntrospectRequest{
		Token:    token,
		ClientID: "admin-client",
		IsAdmin:  true,
	})

	if !resp.Active {
		t.Fatal("expected active=true for admin bypassing aud check")
	}
	if resp.ClientID != "client-a" {
		t.Fatalf("client_id = %q, want %q (original token audience)", resp.ClientID, "client-a")
	}
}

// TestIntrospectMalformedToken verifies that malformed tokens return inactive.
func TestIntrospectMalformedToken(t *testing.T) {
	signer := newTestSigner(t)
	intro := testIntrospector(t, signer)

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"not-jwt", "not-a-jwt-token"},
		{"two-parts", "header.payload"},
		{"four-parts", "a.b.c.d"},
		{"invalid-base64", "!!!.!!!.!!!"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := intro.Introspect(context.Background(), IntrospectRequest{
				Token:    tc.token,
				ClientID: "demo-client",
			})
			if resp.Active {
				t.Fatalf("expected active=false for malformed token %q", tc.name)
			}
		})
	}
}

// TestIntrospectUnknownKid verifies that tokens with unknown kid return inactive.
func TestIntrospectUnknownKid(t *testing.T) {
	signer1 := newTestSigner(t)
	signer2 := newTestSigner(t)

	// Issue token with signer1
	token := issueTestAccessToken(t, signer1, "demo-client")

	// Introspect with signer2 (different kid)
	intro := testIntrospector(t, signer2)
	resp := intro.Introspect(context.Background(), IntrospectRequest{
		Token:    token,
		ClientID: "demo-client",
	})

	if resp.Active {
		t.Fatal("expected active=false for token with unknown kid")
	}
}

// TestIntrospectBloomHitDBError verifies fail-closed on DB error.
func TestIntrospectBloomHitDBError(t *testing.T) {
	signer := newTestSigner(t)
	token := issueTestAccessToken(t, signer, "demo-client")

	// Extract JTI from token
	_, payload, _, err := parseCompactJWT(token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := unmarshalJSON(payload, &claims); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Create filter with the JTI
	filter := NewInMemoryRevocationFilter()
	filter.Add(claims.JTI)

	// Create DB checker that returns an error
	checker := &mockRevokedJTIChecker{err: errors.New("db error")}

	intro := testIntrospector(t, signer, func(cfg *IntrospectConfig) {
		cfg.Filter = filter
		cfg.RevokedChecker = checker
	})

	resp := intro.Introspect(context.Background(), IntrospectRequest{
		Token:    token,
		ClientID: "demo-client",
	})

	// Should fail closed (treat as revoked on DB error)
	if resp.Active {
		t.Fatal("expected active=false when DB checker errors (fail-closed)")
	}
}

// TestIntrospectNoBloomFilterConfigured verifies tokens work without bloom filter.
func TestIntrospectNoBloomFilterConfigured(t *testing.T) {
	signer := newTestSigner(t)
	token := issueTestAccessToken(t, signer, "demo-client")

	// No filter configured
	intro := testIntrospector(t, signer)

	resp := intro.Introspect(context.Background(), IntrospectRequest{
		Token:    token,
		ClientID: "demo-client",
	})

	if !resp.Active {
		t.Fatal("expected active=true when no bloom filter is configured")
	}
}

// TestIntrospectMultipleSigners verifies rotation overlap support.
func TestIntrospectMultipleSigners(t *testing.T) {
	signer1 := newTestSigner(t)
	signer2 := newTestSigner(t)

	// Issue tokens with each signer
	token1 := issueTestAccessToken(t, signer1, "demo-client")
	token2 := issueTestAccessToken(t, signer2, "demo-client")

	// Introspector with both signers (rotation overlap)
	intro := NewIntrospector(IntrospectConfig{
		Signers: []crypto.Signer{signer1, signer2},
		Now:     fixedNow,
	})

	// Both tokens should validate
	resp1 := intro.Introspect(context.Background(), IntrospectRequest{
		Token:    token1,
		ClientID: "demo-client",
	})
	if !resp1.Active {
		t.Fatal("expected token from signer1 to be active")
	}

	resp2 := intro.Introspect(context.Background(), IntrospectRequest{
		Token:    token2,
		ClientID: "demo-client",
	})
	if !resp2.Active {
		t.Fatal("expected token from signer2 to be active")
	}
}

// mockRevokedJTIChecker is a test double for RevokedJTIChecker.
type mockRevokedJTIChecker struct {
	revoked map[string]bool
	err     error
}

func (m *mockRevokedJTIChecker) IsRevoked(_ context.Context, jti string) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	return m.revoked[jti], nil
}

// unmarshalJSON is a helper to unmarshal JSON payload.
func unmarshalJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
