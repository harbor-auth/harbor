package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/harbor/harbor/internal/crypto"
)

// idTokenTTLSeconds is the ID token lifetime (10 min; docs/DESIGN.md §3.5).
const idTokenTTLSeconds = 600

// jwtHeader is the fixed JOSE header for Harbor's ES256 JWTs. Field order
// (alg, typ, kid) is fixed for byte-stable golden vectors.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// idTokenClaims are the claims for an OIDC ID token. nonce is omitted when empty.
type idTokenClaims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience string   `json:"aud"`
	Azp      string   `json:"azp"` // authorized party — equals client_id when aud is single-valued (OIDC Core §2)
	Expiry   int64    `json:"exp"`
	IssuedAt int64    `json:"iat"`
	AuthTime int64    `json:"auth_time"`
	ACR      string   `json:"acr,omitempty"` // authentication context class reference (OIDC Core §2)
	AMR      []string `json:"amr,omitempty"` // authentication methods references (OIDC Core §2)
	Nonce    string   `json:"nonce,omitempty"`
	JTI      string   `json:"jti"`
}

// accessTokenClaims are the claims for an access token (RFC 9068 JWT profile).
type accessTokenClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	Expiry   int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
	Scope    string `json:"scope"`
	JTI      string `json:"jti"`
}

// JWTIssuer implements [TokenIssuer] by minting real ES256-signed JWTs. The
// [crypto.Signer] holds the private key (HSM in prod, in-process in dev), so
// the /token exchange logic never touches key material.
type JWTIssuer struct {
	signer crypto.Signer
	now    func() time.Time
}

// Compile-time proof that JWTIssuer implements TokenIssuer.
var _ TokenIssuer = (*JWTIssuer)(nil)

// JWTIssuerConfig configures a JWTIssuer.
type JWTIssuerConfig struct {
	Signer crypto.Signer
	// Now overrides the clock for deterministic tests. Defaults to time.Now.
	Now func() time.Time
}

// NewJWTIssuer returns a JWTIssuer backed by cfg.Signer.
func NewJWTIssuer(cfg JWTIssuerConfig) *JWTIssuer {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &JWTIssuer{signer: cfg.Signer, now: now}
}

// Issue implements [TokenIssuer]: mints a signed ID token and access token.
// The sub claim is always the PPID (p.Subject); no PII beyond consented scopes
// is ever placed in the claim set (docs/DESIGN.md §3.2, §6.5).
//
//harbor:invariant INV-JWT-SUB-IS-PPID
//harbor:invariant INV-JWT-NO-PII
func (j *JWTIssuer) Issue(_ context.Context, p IssueParams) (IssuedTokens, error) {
	now := j.now()
	idTokenJTI, err := newJTI()
	if err != nil {
		return IssuedTokens{}, fmt.Errorf("jwt: generate id_token jti: %w", err)
	}
	accessTokenJTI, err := newJTI()
	if err != nil {
		return IssuedTokens{}, fmt.Errorf("jwt: generate access_token jti: %w", err)
	}

	idToken, err := j.signJWT("JWT", idTokenClaims{
		Issuer:   p.Issuer,
		Subject:  p.Subject,
		Audience: p.ClientID,
		Azp:      p.ClientID, // OIDC Core §2: azp = client_id when aud is single-valued
		Expiry:   now.Add(idTokenTTLSeconds * time.Second).Unix(),
		IssuedAt: now.Unix(),
		AuthTime: p.AuthTime,
		ACR:      p.ACR,
		AMR:      p.AMR,
		Nonce:    p.Nonce,
		JTI:      idTokenJTI,
	})
	if err != nil {
		return IssuedTokens{}, fmt.Errorf("jwt: sign ID token: %w", err)
	}

	accessToken, err := j.signJWT("at+JWT", accessTokenClaims{
		Issuer:   p.Issuer,
		Subject:  p.Subject,
		Audience: p.ClientID,
		Expiry:   now.Add(accessTokenTTLSeconds * time.Second).Unix(),
		IssuedAt: now.Unix(),
		Scope:    p.Scope,
		JTI:      accessTokenJTI,
	})
	if err != nil {
		return IssuedTokens{}, fmt.Errorf("jwt: sign access token: %w", err)
	}

	return IssuedTokens{
		AccessToken: accessToken,
		IDToken:     idToken,
		TokenType:   "Bearer",
		ExpiresIn:   accessTokenTTLSeconds,
		Scope:       p.Scope,
	}, nil
}

// signJWT builds and signs a compact JWT (header.payload.sig). typ is the JOSE
// header "typ" ("JWT" for ID tokens, "at+JWT" for access tokens per RFC 9068).
func (j *JWTIssuer) signJWT(typ string, claims any) (string, error) {
	headerJSON, err := json.Marshal(jwtHeader{
		Alg: "ES256",
		Typ: typ,
		Kid: j.signer.KeyID(),
	})
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	sig, err := j.signer.Sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// newJTI returns a random 256-bit URL-safe JWT ID.
func newJTI() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// parseCompactJWT splits a compact JWT and returns the decoded header, payload,
// and signature bytes. It does NOT verify the signature. Package-private: used
// by tests to inspect issued tokens.
func parseCompactJWT(token string) (header, payload, sig []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("jwt: invalid compact format")
	}
	if header, err = base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		return nil, nil, nil, fmt.Errorf("jwt: header decode: %w", err)
	}
	if payload, err = base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		return nil, nil, nil, fmt.Errorf("jwt: payload decode: %w", err)
	}
	if sig, err = base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
		return nil, nil, nil, fmt.Errorf("jwt: sig decode: %w", err)
	}
	return header, payload, sig, nil
}
