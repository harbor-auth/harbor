package oidcapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/openapi"
	"github.com/harbor-auth/harbor/internal/oidc"
)

// newFlowServerWithIssuer builds a full /authorize -> /token -> /userinfo flow
// server pinned to the given region issuer, backed by the supplied signer.
// Sharing one signer across two region servers lets each verify the other's
// token SIGNATURES, so a cross-region rejection is attributable solely to the
// issuer/host coherence guard — not to a signature failure (OpenSpec
// regional-data-residency-routing REQ-001, REQ-002).
func newFlowServerWithIssuer(t *testing.T, issuer string, signer crypto.Signer) *httptest.Server {
	t.Helper()
	clients := oidc.NewInMemoryClientRegistry()
	clients.Put(oidc.Client{
		ID:            testClientID,
		SectorID:      "localhost", // required for PPID derivation (§3.2)
		RedirectURIs:  []string{testRedirectURI},
		ScopesAllowed: []string{"openid", "profile", "email", "offline_access"},
	})
	svc := oidc.NewService(oidc.ServiceConfig{
		Issuer:   issuer,
		Clients:  clients,
		Codes:    oidc.NewInMemoryAuthCodeStore(),
		Tokens:   oidc.NewJWTIssuer(oidc.JWTIssuerConfig{Signer: signer}),
		Sessions: oidc.NewStubSessionResolver("demo-subject-ppid"),
	})
	srv := New(Config{
		Issuer:  issuer,
		Service: svc,
		Signers: []crypto.Signer{signer},
	})
	h := openapi.HandlerFromMux(srv, http.NewServeMux())
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

// accessTokenIssuer decodes the iss claim from a compact JWT access token.
func accessTokenIssuer(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed access token: %d parts", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims.Issuer
}

// TestUserInfo_IssClaimMatchesRegion verifies that the access token minted by a
// region server carries an iss claim equal to that region's issuer, so the
// token is bound to the region that issued it (OpenSpec
// regional-data-residency-routing REQ-001, REQ-002).
func TestUserInfo_IssClaimMatchesRegion(t *testing.T) {
	signer, err := crypto.NewLocalSigner()
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	const euIssuer = "https://eu.harbor.id"
	eu := newFlowServerWithIssuer(t, euIssuer, signer)

	accessToken := mintAccessToken(t, eu)
	if got := accessTokenIssuer(t, accessToken); got != euIssuer {
		t.Fatalf("access token iss = %q, want %q", got, euIssuer)
	}
}

// TestUserInfo_RejectsCrossRegionToken proves /userinfo enforces issuer/host
// coherence at the HTTP layer: a token minted on the EU region is accepted by
// the EU /userinfo but REJECTED (401 invalid_token) by the US /userinfo. Both
// regions share the same signing key, so the signature itself verifies on
// either surface — the rejection is therefore attributable to the region
// issuer mismatch alone (OpenSpec regional-data-residency-routing REQ-001,
// REQ-002).
func TestUserInfo_RejectsCrossRegionToken(t *testing.T) {
	// Shared signer: the US surface CAN verify the EU token's signature, so the
	// only remaining reason to reject is the region issuer mismatch.
	signer, err := crypto.NewLocalSigner()
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	eu := newFlowServerWithIssuer(t, "https://eu.harbor.id", signer)
	us := newFlowServerWithIssuer(t, "https://us.harbor.id", signer)

	euToken := mintAccessToken(t, eu)

	// Same-region: the EU token is accepted by the EU /userinfo.
	sameRegion := getUserInfo(t, eu, euToken)
	defer func() { _ = sameRegion.Body.Close() }()
	if sameRegion.StatusCode != http.StatusOK {
		t.Fatalf("same-region /userinfo status = %d, want 200", sameRegion.StatusCode)
	}

	// Cross-region: the EU token is rejected by the US /userinfo with 401.
	crossRegion := getUserInfo(t, us, euToken)
	defer func() { _ = crossRegion.Body.Close() }()
	if crossRegion.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-region /userinfo status = %d, want 401", crossRegion.StatusCode)
	}
	if errCode := decodeOAuthErrorCode(t, crossRegion); errCode != "invalid_token" {
		t.Fatalf("cross-region error = %q, want invalid_token", errCode)
	}
}
