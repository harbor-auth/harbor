package oidctest

import (
	"context"

	harboroidc "github.com/harbor-auth/harbor/internal/oidc"
)

const testAccessTokenTTLSeconds = 600

// placeholderIssuer returns OBVIOUSLY-FAKE, UNSIGNED tokens.
//
// SCAFFOLD — NOT SECURE, NEVER FOR PRODUCTION. Real tokens are asymmetric-signed
// JWTs (ES256/EdDSA) whose private key never leaves the regional HSM, published
// via JWKS (docs/DESIGN.md §3.3, §7.3). This stub exists only so the /token
// exchange (single-use codes, PKCE, error channels) can be built and tested
// end-to-end before the signing stack lands. The token strings are deliberately
// self-identifying so they can never be mistaken for real credentials.
type placeholderIssuer struct{}

// NewPlaceholderIssuer returns the SCAFFOLD issuer. Replace with the HSM-backed
// JWT signer (docs/DESIGN.md §7.3) before any real deployment.
func NewPlaceholderIssuer() harboroidc.TokenIssuer { return placeholderIssuer{} }

// Issue implements harboroidc.TokenIssuer with unsigned placeholder tokens.
func (placeholderIssuer) Issue(_ context.Context, p harboroidc.IssueParams) (harboroidc.IssuedTokens, error) {
	return harboroidc.IssuedTokens{
		AccessToken: "UNSIGNED_PLACEHOLDER_ACCESS_TOKEN." + p.Subject,
		IDToken:     "UNSIGNED_PLACEHOLDER_ID_TOKEN." + p.Subject,
		TokenType:   "Bearer",
		ExpiresIn:   testAccessTokenTTLSeconds,
		Scope:       p.Scope,
	}, nil
}
