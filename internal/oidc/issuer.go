package oidc

import "context"

// IssueParams are the inputs to minting tokens for a successful code exchange.
type IssueParams struct {
	Issuer   string
	Subject  string // PPID (docs/DESIGN.md §3.2)
	ClientID string // becomes the token `aud`
	Scope    string
	Nonce    string // bound into the id_token later
}

// IssuedTokens is the result of a successful token issuance.
type IssuedTokens struct {
	AccessToken string
	IDToken     string
	TokenType   string
	ExpiresIn   int // seconds
	Scope       string
}

// TokenIssuer mints the access + ID tokens for a grant. Isolating it behind an
// interface keeps the flow logic testable and lets the real ES256/EdDSA signer
// (keys in the regional HSM; docs/DESIGN.md §7.3) drop in without touching the
// /token exchange logic.
type TokenIssuer interface {
	Issue(ctx context.Context, p IssueParams) (IssuedTokens, error)
}

// accessTokenTTLSeconds is the placeholder access-token lifetime (~10 min;
// docs/DESIGN.md §3.5). Short by design.
const accessTokenTTLSeconds = 600

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
func NewPlaceholderIssuer() TokenIssuer { return placeholderIssuer{} }

// Issue implements TokenIssuer with unsigned placeholder tokens.
func (placeholderIssuer) Issue(_ context.Context, p IssueParams) (IssuedTokens, error) {
	return IssuedTokens{
		AccessToken: "UNSIGNED_PLACEHOLDER_ACCESS_TOKEN." + p.Subject,
		IDToken:     "UNSIGNED_PLACEHOLDER_ID_TOKEN." + p.Subject,
		TokenType:   "Bearer",
		ExpiresIn:   accessTokenTTLSeconds,
		Scope:       p.Scope,
	}, nil
}
