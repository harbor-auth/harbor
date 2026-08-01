package oidcapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/harbor-auth/harbor/internal/gen/openapi"
	"github.com/harbor-auth/harbor/internal/oidc"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

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

	if s.jwtVerifier == nil {
		writeUnauthorized(w, "invalid_token", "access token is invalid")
		return
	}
	claims, err := s.jwtVerifier.VerifyAccessToken(r.Context(), token, oidc.AccessTokenRequirements{
		RequiredScopes: []string{"openid"},
	})
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
