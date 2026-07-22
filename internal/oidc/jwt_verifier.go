// Package oidc jwt_verifier.go provides JWT verification with emergency
// revocation checking via bloom filter (DESIGN.md §3.5).
package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/harbor-auth/harbor/internal/crypto"
)

// ErrTokenRevoked is returned when a JWT's JTI is found in the revocation list.
var ErrTokenRevoked = errors.New("token has been revoked")

// ErrTokenExpired is returned when a JWT's exp claim is in the past.
var ErrTokenExpired = errors.New("token has expired")

// ErrTokenInvalid is returned when a JWT cannot be parsed or verified.
var ErrTokenInvalid = errors.New("token is invalid")

// ErrIssuerMismatch is returned when a JWT's iss claim does not match the
// region issuer this verifier is pinned to. It enforces region issuer/host
// coherence: a token minted on one region (e.g. https://eu.harbor.id) must not
// verify on another region's surface (OpenSpec regional-data-residency-routing
// REQ-001, REQ-002).
var ErrIssuerMismatch = errors.New("token issuer does not match expected region issuer")

// RevokedJTIChecker checks if a JTI is revoked. Used for DB introspection
// fallback when the bloom filter returns a hit.
type RevokedJTIChecker interface {
	// IsRevoked checks if the given JTI is in the revoked_jtis table.
	// Returns (true, nil) if revoked, (false, nil) if not found, or
	// (false, err) on DB error.
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// JWTVerifier verifies JWTs and checks for emergency revocation via bloom
// filter. The verification pipeline is:
//
//  1. Parse and decode the JWT
//  2. Verify signature against the signer's public key
//  3. Check exp claim against current time
//  4. Check bloom filter for JTI (MightContain)
//  5. On filter hit: DB introspection to confirm (IsRevoked)
//
// Step 4 adds ~100ns overhead. Step 5 only fires on bloom filter hits
// (target: 1 in 1,000,000 with default configuration).
type JWTVerifier struct {
	pubKey         *ecdsa.PublicKey
	filter         RevocationFilter
	revokedChecker RevokedJTIChecker // nil = skip DB introspection (test mode)
	expectedIssuer string            // "" = do not enforce issuer coherence
	now            func() time.Time
}

// JWTVerifierConfig configures a JWTVerifier.
type JWTVerifierConfig struct {
	// Signer provides the public key for signature verification.
	// The JWK is extracted from the signer to get the public key.
	Signer crypto.Signer

	// Filter is the in-process bloom filter for revoked JTIs.
	// If nil, revocation checking is skipped.
	Filter RevocationFilter

	// RevokedChecker performs DB introspection on bloom filter hits.
	// If nil, filter hits are treated as confirmed revocations (fail-closed).
	RevokedChecker RevokedJTIChecker

	// ExpectedIssuer, when non-empty, is the region issuer URL this verifier is
	// pinned to (e.g. https://eu.harbor.id). Verify rejects any token whose iss
	// claim differs, enforcing region issuer/host coherence so a token minted on
	// one region cannot be verified/introspected on another region's surface
	// (OpenSpec regional-data-residency-routing REQ-001, REQ-002). Empty means
	// the check is skipped (backwards compatible).
	ExpectedIssuer string

	// Now overrides the clock for deterministic tests. Defaults to time.Now.
	Now func() time.Time
}

// NewJWTVerifier creates a JWTVerifier with the given configuration.
// Returns an error if the signer's public key cannot be extracted.
func NewJWTVerifier(cfg JWTVerifierConfig) (*JWTVerifier, error) {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	// Extract the public key from the signer's JWK
	var pubKey *ecdsa.PublicKey
	if cfg.Signer != nil {
		jwk := cfg.Signer.PublicJWK()
		var err error
		pubKey, err = jwk.ToPublicKey()
		if err != nil {
			return nil, fmt.Errorf("jwt verifier: extract public key: %w", err)
		}
	}

	return &JWTVerifier{
		pubKey:         pubKey,
		filter:         cfg.Filter,
		revokedChecker: cfg.RevokedChecker,
		expectedIssuer: cfg.ExpectedIssuer,
		now:            now,
	}, nil
}

// VerifiedClaims contains the validated claims from a verified JWT.
type VerifiedClaims struct {
	Issuer   string
	Subject  string
	Audience string
	Expiry   time.Time
	IssuedAt time.Time
	JTI      string
	Scope    string // access tokens only
}

// Verify parses, verifies, and checks revocation status of a JWT.
// Returns the verified claims on success, or an error if:
//   - The JWT is malformed (ErrTokenInvalid)
//   - The signature is invalid (ErrTokenInvalid)
//   - The token has expired (ErrTokenExpired)
//   - The JTI is revoked (ErrTokenRevoked)
//
//harbor:invariant INV-EMERGENCY-REVOCATION
func (v *JWTVerifier) Verify(ctx context.Context, token string) (*VerifiedClaims, error) {
	// Step 1: Parse the JWT
	header, payload, sig, err := parseCompactJWT(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTokenInvalid, err)
	}

	// Verify header algorithm
	var h jwtHeader
	if err := json.Unmarshal(header, &h); err != nil {
		return nil, fmt.Errorf("%w: invalid header", ErrTokenInvalid)
	}
	if h.Alg != "ES256" {
		return nil, fmt.Errorf("%w: unsupported algorithm %s", ErrTokenInvalid, h.Alg)
	}

	// Step 2: Verify signature
	if v.pubKey == nil {
		return nil, fmt.Errorf("%w: no public key configured", ErrTokenInvalid)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: invalid format", ErrTokenInvalid)
	}
	signingInput := parts[0] + "." + parts[1]
	if !verifyES256Signature(v.pubKey, []byte(signingInput), sig) {
		return nil, fmt.Errorf("%w: signature verification failed", ErrTokenInvalid)
	}

	// Parse claims (support both ID tokens and access tokens)
	claims, err := v.parseClaims(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTokenInvalid, err)
	}

	// Region issuer/host coherence: when the verifier is pinned to a region
	// issuer, a token whose iss claim names a DIFFERENT region must be rejected
	// even though its signature is valid (shared/rotated keys do not imply
	// cross-region acceptance). This prevents a token minted on eu.harbor.id
	// from being accepted on the us.harbor.id surface (OpenSpec
	// regional-data-residency-routing REQ-001, REQ-002).
	if v.expectedIssuer != "" && claims.Issuer != v.expectedIssuer {
		return nil, fmt.Errorf("%w: token iss %q != expected %q", ErrIssuerMismatch, claims.Issuer, v.expectedIssuer)
	}

	// Step 3: Check expiry
	if v.now().After(claims.Expiry) {
		return nil, ErrTokenExpired
	}

	// Step 4: Check bloom filter for JTI (emergency revocation)
	if v.filter != nil && claims.JTI != "" {
		if v.filter.MightContain(claims.JTI) {
			// Step 5: Bloom filter hit - confirm via DB introspection
			revoked, err := v.confirmRevocation(ctx, claims.JTI)
			if err != nil {
				// DB error - fail closed (treat as revoked for safety)
				return nil, fmt.Errorf("%w: revocation check failed: %w", ErrTokenRevoked, err)
			}
			if revoked {
				return nil, ErrTokenRevoked
			}
			// False positive - token is valid
		}
	}

	return claims, nil
}

// parseClaims extracts claims from JWT payload. Supports both ID tokens
// (no JTI) and access tokens (with JTI and scope).
func (v *JWTVerifier) parseClaims(payload []byte) (*VerifiedClaims, error) {
	// Try access token claims first (has JTI)
	var atClaims struct {
		Issuer   string `json:"iss"`
		Subject  string `json:"sub"`
		Audience string `json:"aud"`
		Expiry   int64  `json:"exp"`
		IssuedAt int64  `json:"iat"`
		JTI      string `json:"jti"`
		Scope    string `json:"scope"`
	}
	if err := json.Unmarshal(payload, &atClaims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	return &VerifiedClaims{
		Issuer:   atClaims.Issuer,
		Subject:  atClaims.Subject,
		Audience: atClaims.Audience,
		Expiry:   time.Unix(atClaims.Expiry, 0),
		IssuedAt: time.Unix(atClaims.IssuedAt, 0),
		JTI:      atClaims.JTI,
		Scope:    atClaims.Scope,
	}, nil
}

// confirmRevocation checks with the DB whether a JTI is actually revoked.
// Returns true if confirmed revoked, false if not found (false positive).
func (v *JWTVerifier) confirmRevocation(ctx context.Context, jti string) (bool, error) {
	if v.revokedChecker == nil {
		// No DB checker configured - fail closed (treat filter hit as revoked)
		return true, nil
	}
	return v.revokedChecker.IsRevoked(ctx, jti)
}

// VerifyAccessToken is a convenience method that verifies an access token
// and returns an error if the token is invalid, expired, or revoked.
func (v *JWTVerifier) VerifyAccessToken(ctx context.Context, token string) (*VerifiedClaims, error) {
	claims, err := v.Verify(ctx, token)
	if err != nil {
		return nil, err
	}
	// Access tokens must have a JTI
	if claims.JTI == "" {
		return nil, fmt.Errorf("%w: access token missing jti claim", ErrTokenInvalid)
	}
	return claims, nil
}

// VerifySignatureOnly verifies a JWT's signature and issuer but SKIPS the
// expiry check. This is used for id_token_hint validation in RP-Initiated
// Logout (OIDC RP-Initiated Logout 1.0) where users may log out with expired
// tokens — the signature proves the token was genuinely issued by Harbor, and
// the sub claim identifies the user/client pair for session revocation.
//
// Returns the verified claims on success, or an error if:
//   - The JWT is malformed (ErrTokenInvalid)
//   - The signature is invalid (ErrTokenInvalid)
//   - The issuer doesn't match (ErrIssuerMismatch)
//
// NOTE: This method does NOT check revocation status since id_token_hint
// validation doesn't need it — we're revoking sessions, not granting access.
func (v *JWTVerifier) VerifySignatureOnly(ctx context.Context, token string) (*VerifiedClaims, error) {
	// Step 1: Parse the JWT
	header, payload, sig, err := parseCompactJWT(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTokenInvalid, err)
	}

	// Verify header algorithm
	var h jwtHeader
	if err := json.Unmarshal(header, &h); err != nil {
		return nil, fmt.Errorf("%w: invalid header", ErrTokenInvalid)
	}
	if h.Alg != "ES256" {
		return nil, fmt.Errorf("%w: unsupported algorithm %s", ErrTokenInvalid, h.Alg)
	}

	// Step 2: Verify signature
	if v.pubKey == nil {
		return nil, fmt.Errorf("%w: no public key configured", ErrTokenInvalid)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: invalid format", ErrTokenInvalid)
	}
	signingInput := parts[0] + "." + parts[1]
	if !verifyES256Signature(v.pubKey, []byte(signingInput), sig) {
		return nil, fmt.Errorf("%w: signature verification failed", ErrTokenInvalid)
	}

	// Parse claims
	claims, err := v.parseClaims(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTokenInvalid, err)
	}

	// Step 3: Check issuer coherence (skip expiry check intentionally)
	if v.expectedIssuer != "" && claims.Issuer != v.expectedIssuer {
		return nil, fmt.Errorf("%w: token iss %q != expected %q", ErrIssuerMismatch, claims.Issuer, v.expectedIssuer)
	}

	// NOTE: Expiry check is intentionally skipped — users may log out with
	// expired tokens, and we only need the signature to prove authenticity.

	return claims, nil
}

// DBRevokedJTIChecker adapts DBRevokedJTIStore to the RevokedJTIChecker interface.
type DBRevokedJTIChecker struct {
	store interface {
		GetByJTI(ctx context.Context, jti string) (interface{}, bool, error)
	}
}

// NewDBRevokedJTIChecker creates a checker backed by a DBRevokedJTIStore.
// The store parameter should be *clients.DBRevokedJTIStore.
func NewDBRevokedJTIChecker(store interface {
	GetByJTI(ctx context.Context, jti string) (interface{}, bool, error)
}) *DBRevokedJTIChecker {
	return &DBRevokedJTIChecker{store: store}
}

// IsRevoked implements RevokedJTIChecker.
func (c *DBRevokedJTIChecker) IsRevoked(ctx context.Context, jti string) (bool, error) {
	_, found, err := c.store.GetByJTI(ctx, jti)
	if err != nil {
		return false, err
	}
	return found, nil
}

// noopRevokedJTIChecker always returns false (no revocations).
// Used for testing when no DB is available.
type noopRevokedJTIChecker struct{}

func (noopRevokedJTIChecker) IsRevoked(context.Context, string) (bool, error) {
	return false, nil
}

// NewNoopRevokedJTIChecker returns a checker that never finds revocations.
// Use for testing or when emergency revocation is not configured.
func NewNoopRevokedJTIChecker() RevokedJTIChecker {
	return noopRevokedJTIChecker{}
}

// verifyES256Signature verifies an ES256 (ECDSA P-256 SHA-256) signature.
// sigBytes must be the raw R||S format (64 bytes total, 32 bytes each).
func verifyES256Signature(pubKey *ecdsa.PublicKey, signingInput, sigBytes []byte) bool {
	if len(sigBytes) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	digest := sha256.Sum256(signingInput)
	return ecdsa.Verify(pubKey, digest[:], r, s)
}
