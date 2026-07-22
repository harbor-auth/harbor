package oidc

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/harbor-auth/harbor/internal/crypto"
)

// IntrospectRequest is the domain model for an RFC 7662 token introspection
// request. It is populated from the HTTP layer (oidcapi) after parsing the
// form-encoded body and authenticating the caller.
//
// Fields:
//   - Token: the access or refresh token to introspect (required).
//   - TokenTypeHint: optional hint ("access_token" or "refresh_token") to
//     optimize lookup order.
//   - ClientID: the authenticated caller's client_id (from Basic auth).
//   - IsAdmin: true when the caller authenticated with an admin Bearer token;
//     admin callers may introspect any token (cross-client allowed).
type IntrospectRequest struct {
	// Token is the access or refresh token to introspect. May be a JWT
	// (access token) or an opaque string (refresh token).
	Token string

	// TokenTypeHint is an optional hint about the token type. If omitted, the
	// introspection handler tries both access and refresh token lookups.
	// Valid values: "access_token", "refresh_token".
	TokenTypeHint string

	// ClientID is the authenticated caller's client_id. For Basic auth, this
	// is the username; for admin Bearer tokens, this may be empty (admin
	// callers are identified by IsAdmin=true instead).
	ClientID string

	// IsAdmin is true when the caller authenticated with an admin Bearer token.
	// Admin callers may introspect any token regardless of audience; non-admin
	// callers may only introspect tokens whose `aud` matches their ClientID
	// (cross-client isolation, RFC 7662 §2.1).
	IsAdmin bool
}

// IntrospectResponse is the domain model for an RFC 7662 token introspection
// response. The Active field is always present; additional claims are only
// populated when Active is true.
//
// For inactive tokens (expired, revoked, malformed, or cross-client queries),
// only Active=false is set — no other claims are leaked (enumeration
// resistance, docs/DESIGN.md §3.3, §3.5).
type IntrospectResponse struct {
	// Active is true if the token is valid, not expired, and not revoked.
	// False otherwise (expired, revoked, malformed, or cross-client query).
	Active bool

	// Sub is the pairwise subject identifier (PPID) for the token's user.
	// Only present when Active is true.
	Sub string

	// Scope is the space-delimited list of granted scopes.
	// Only present when Active is true.
	Scope string

	// ClientID is the client_id that the token was issued to.
	// Only present when Active is true.
	ClientID string

	// Exp is the token expiration time as Unix timestamp (seconds since epoch).
	// Only present when Active is true.
	Exp int64

	// Iat is the token issuance time as Unix timestamp (seconds since epoch).
	// Only present when Active is true.
	Iat int64

	// Iss is the issuer URL that minted the token.
	// Only present when Active is true.
	Iss string

	// Aud is the intended audience (typically the client_id).
	// Only present when Active is true.
	Aud string

	// Jti is the unique token identifier (JWT ID).
	// Only present when Active is true and the token is a JWT.
	Jti string

	// TokenType is the type of the token (e.g., "Bearer").
	// Only present when Active is true.
	TokenType string
}

// InactiveIntrospectResponse returns an IntrospectResponse with Active=false
// and no other claims. Use this for all negative introspection outcomes
// (expired, revoked, malformed, cross-client) to ensure enumeration resistance.
func InactiveIntrospectResponse() IntrospectResponse {
	return IntrospectResponse{Active: false}
}

// IntrospectConfig holds the dependencies for token introspection.
type IntrospectConfig struct {
	// Signers are the signing keys used to verify access token signatures.
	// The first is the active signer; additional entries support rotation
	// overlap (§7.3).
	Signers []crypto.Signer

	// Filter is the in-process bloom filter for revoked JTIs. If nil,
	// revocation checking is skipped.
	Filter RevocationFilter

	// RevokedChecker performs DB introspection on bloom filter hits.
	// If nil, filter hits are treated as confirmed revocations (fail-closed).
	RevokedChecker RevokedJTIChecker

	// Now overrides the clock for deterministic tests. Defaults to time.Now.
	Now func() time.Time
}

// Introspector handles RFC 7662 token introspection.
type Introspector struct {
	signers        []crypto.Signer
	filter         RevocationFilter
	revokedChecker RevokedJTIChecker
	now            func() time.Time
}

// NewIntrospector creates an Introspector with the given configuration.
func NewIntrospector(cfg IntrospectConfig) *Introspector {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Introspector{
		signers:        cfg.Signers,
		filter:         cfg.Filter,
		revokedChecker: cfg.RevokedChecker,
		now:            now,
	}
}

// Introspect validates an access token and returns its active status and
// metadata. All failure modes (malformed, expired, revoked, cross-client)
// return {active:false} with no other claims for enumeration resistance.
//
// The introspection pipeline is:
//  1. Parse and decode the JWT
//  2. Verify ES256 signature against known signers
//  3. Check exp claim against current time
//  4. Check bloom filter for JTI (MightContain)
//  5. On filter hit: DB introspection to confirm (IsRevoked)
//  6. Enforce aud == req.ClientID unless req.IsAdmin
//
//harbor:invariant INV-INTROSPECT-ENUMERATION-RESISTANCE
func (i *Introspector) Introspect(ctx context.Context, req IntrospectRequest) IntrospectResponse {
	// Step 1: Parse the JWT
	header, payload, sig, err := parseCompactJWT(req.Token)
	if err != nil {
		return InactiveIntrospectResponse()
	}

	// Verify header algorithm
	var h jwtHeader
	if err := json.Unmarshal(header, &h); err != nil {
		return InactiveIntrospectResponse()
	}
	if h.Alg != "ES256" {
		return InactiveIntrospectResponse()
	}

	// Step 2: Verify signature against known signers (match on kid)
	pubKey, err := i.publicKeyByKID(h.Kid)
	if err != nil {
		return InactiveIntrospectResponse()
	}

	parts := strings.Split(req.Token, ".")
	if len(parts) != 3 {
		return InactiveIntrospectResponse()
	}
	signingInput := parts[0] + "." + parts[1]
	if !verifyES256Signature(pubKey, []byte(signingInput), sig) {
		return InactiveIntrospectResponse()
	}

	// Parse claims
	var claims struct {
		Issuer   string `json:"iss"`
		Subject  string `json:"sub"`
		Audience string `json:"aud"`
		Expiry   int64  `json:"exp"`
		IssuedAt int64  `json:"iat"`
		JTI      string `json:"jti"`
		Scope    string `json:"scope"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return InactiveIntrospectResponse()
	}

	// Step 3: Check expiry
	if i.now().After(time.Unix(claims.Expiry, 0)) {
		return InactiveIntrospectResponse()
	}

	// Step 4 & 5: Check bloom filter for JTI (emergency revocation)
	if i.filter != nil && claims.JTI != "" {
		if i.filter.MightContain(claims.JTI) {
			// Bloom filter hit - confirm via DB introspection
			revoked, err := i.confirmRevocation(ctx, claims.JTI)
			if err != nil {
				// DB error - fail closed (treat as revoked for safety)
				return InactiveIntrospectResponse()
			}
			if revoked {
				return InactiveIntrospectResponse()
			}
			// False positive - continue validation
		}
	}

	// Step 6: Cross-client isolation — aud must match caller's client_id
	// unless the caller is an admin (IsAdmin=true).
	if !req.IsAdmin && claims.Audience != req.ClientID {
		return InactiveIntrospectResponse()
	}

	// All checks passed — token is active
	return IntrospectResponse{
		Active:    true,
		Sub:       claims.Subject,
		Scope:     claims.Scope,
		ClientID:  claims.Audience, // aud == client_id for Harbor tokens
		Exp:       claims.Expiry,
		Iat:       claims.IssuedAt,
		Iss:       claims.Issuer,
		Aud:       claims.Audience,
		Jti:       claims.JTI,
		TokenType: "Bearer",
	}
}

// publicKeyByKID returns the ECDSA public key for the given key ID.
func (i *Introspector) publicKeyByKID(kid string) (*ecdsa.PublicKey, error) {
	for _, signer := range i.signers {
		jwk := signer.PublicJWK()
		if jwk.Kid != kid {
			continue
		}
		pub, err := jwk.ToPublicKey()
		if err != nil {
			return nil, err
		}
		return pub, nil
	}
	return nil, errors.New("key not found")
}

// confirmRevocation checks with the DB whether a JTI is actually revoked.
// Returns true if confirmed revoked, false if not found (false positive).
func (i *Introspector) confirmRevocation(ctx context.Context, jti string) (bool, error) {
	if i.revokedChecker == nil {
		// No DB checker configured - fail closed (treat filter hit as revoked)
		return true, nil
	}
	return i.revokedChecker.IsRevoked(ctx, jti)
}
