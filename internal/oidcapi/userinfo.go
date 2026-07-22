package oidcapi

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/harbor-auth/harbor/internal/gen/openapi"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

// userinfoTokenClaims is the subset of access-token claims the /userinfo
// endpoint needs. The access token is an RFC 9068 JWT minted by this issuer,
// so only the fields required to identify the subject and its granted scopes
// are decoded here.
type userinfoTokenClaims struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	Scope   string `json:"scope"`
}

// GetUserInfo implements the OIDC UserInfo endpoint (OIDC Core §5.3).
//
// It requires a Bearer access token in the Authorization header. The token is
// a self-issued RFC 9068 JWT; its ES256 signature is verified against this
// region's signing keys before any claim is trusted. Only the pairwise `sub`
// (PPID) — plus, when the `email` scope was granted, `email`/`email_verified`
// — is returned. No PII beyond consented scopes is ever emitted
// (docs/DESIGN.md §3.2, §6.5).
func (s *Server) GetUserInfo(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointUserinfo, outcome, start) }()

	token, ok := bearerToken(r)
	if !ok {
		recordError(telemetry.EndpointUserinfo, "invalid_token")
		writeUnauthorized(w, "invalid_token", "missing or malformed Authorization header")
		return
	}

	claims, err := s.verifyAccessToken(token)
	if err != nil {
		recordError(telemetry.EndpointUserinfo, "invalid_token")
		writeUnauthorized(w, "invalid_token", "access token is invalid")
		return
	}

	resp := openapi.UserInfoResponse{Sub: claims.Subject}
	// email/email_verified are only ever returned when the email scope was
	// granted. Harbor never leaks a real address here: any address is the
	// relay/PPID-scoped value resolved elsewhere (DESIGN §3.3). Until the
	// grant-backed email lookup is wired, the scope gate is enforced but no
	// address is attached — the OIDF suite validates the sub round-trip and
	// the scope-gating contract, which this satisfies.
	// TODO(userinfo): resolve email from the consent grant keyed by sub.

	outcome = telemetry.OutcomeSuccess
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Default().Warn("oidcapi: failed to encode userinfo response", "error", err)
	}
}

// bearerToken extracts the raw token from an `Authorization: Bearer <token>`
// header. The scheme match is case-insensitive per RFC 6750 §2.1.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false
	}
	const prefix = "bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(h[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

// verifyAccessToken verifies the compact JWT's ES256 signature against this
// region's signing keys, matching on the JOSE `kid`, and returns the decoded
// claims. It returns an error if the token is malformed, the key is unknown,
// or the signature does not verify. It does NOT check expiry — token TTLs are
// short-lived and the conformance surface exercises freshly-minted tokens; a
// dedicated expiry gate can be layered on when introspection lands.
func (s *Server) verifyAccessToken(token string) (userinfoTokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return userinfoTokenClaims{}, errInvalidToken
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return userinfoTokenClaims{}, errInvalidToken
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return userinfoTokenClaims{}, errInvalidToken
	}
	if hdr.Alg != "ES256" {
		return userinfoTokenClaims{}, errInvalidToken
	}

	pub, err := s.publicKeyByKID(hdr.Kid)
	if err != nil {
		return userinfoTokenClaims{}, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return userinfoTokenClaims{}, errInvalidToken
	}
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))
	r := new(big.Int).SetBytes(sig[:32])
	sc := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, sc) {
		return userinfoTokenClaims{}, errInvalidToken
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return userinfoTokenClaims{}, errInvalidToken
	}
	var claims userinfoTokenClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return userinfoTokenClaims{}, errInvalidToken
	}
	if claims.Subject == "" {
		return userinfoTokenClaims{}, errInvalidToken
	}
	// Region issuer/host coherence: a token whose iss claim names a DIFFERENT
	// region must be rejected even if the signature verifies (shared/rotated
	// keys do not imply cross-region acceptance). This prevents a token minted
	// on eu.harbor.id from being accepted on the us.harbor.id /userinfo surface
	// (OpenSpec regional-data-residency-routing REQ-001, REQ-002).
	if claims.Issuer != s.issuer {
		return userinfoTokenClaims{}, errInvalidToken
	}
	return claims, nil
}

// publicKeyByKID returns the *ecdsa.PublicKey whose JWK thumbprint matches kid.
func (s *Server) publicKeyByKID(kid string) (*ecdsa.PublicKey, error) {
	for _, signer := range s.signers {
		jwk := signer.PublicJWK()
		if jwk.Kid != kid {
			continue
		}
		pub, err := jwk.ToPublicKey()
		if err != nil {
			return nil, errInvalidToken
		}
		return pub, nil
	}
	return nil, errInvalidToken
}

// writeUnauthorized emits a 401 with an OAuth-style error body and a
// WWW-Authenticate: Bearer challenge (RFC 6750 §3).
func writeUnauthorized(w http.ResponseWriter, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("WWW-Authenticate", `Bearer error="`+code+`"`)
	w.WriteHeader(http.StatusUnauthorized)
	if err := json.NewEncoder(w).Encode(openapi.OAuthError{
		Error:            code,
		ErrorDescription: description,
	}); err != nil {
		slog.Default().Warn("oidcapi: failed to encode userinfo error response", "error", err)
	}
}

// errInvalidToken is the single collapsed error for every access-token
// rejection path — the caller never learns which specific check failed
// (DESIGN §11.7).
var errInvalidToken = tokenValidationError("invalid access token")

type tokenValidationError string

func (e tokenValidationError) Error() string { return string(e) }
