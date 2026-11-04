package oidcapi

import (
	"encoding/json"
	"errors"
	"github.com/oapi-codegen/runtime/types"
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

	if s.grants == nil || s.clients == nil || s.userInfoSource == nil {
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "UserInfo is unavailable")
		return
	}
	if claims.GrantID == "" {
		writeUnauthorized(w, "invalid_token", "access token is invalid")
		return
	}
	client, found := s.clients.Lookup(r.Context(), claims.Audience)
	if !found || client.ID != claims.Audience {
		writeUnauthorized(w, "invalid_token", "access token is invalid")
		return
	}
	grant, found, err := s.grants.FindGrantByPPID(r.Context(), claims.Subject, claims.Audience)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "UserInfo is unavailable")
		return
	}
	if !found || grant.ID != claims.GrantID || !hasScope(strings.Join(oidc.ConsentedScopes(grant), " "), "openid") || !hasScope(strings.Join(client.ScopesAllowed, " "), "openid") {
		writeUnauthorized(w, "invalid_token", "access token is invalid")
		return
	}
	// All three permission sets must allow disclosure: token, live grant and
	// current application policy. Expanding a grant never expands an old token.
	shareEmail := hasScope(claims.Scope, "email") && hasScope(strings.Join(oidc.ConsentedScopes(grant), " "), "email") && hasScope(strings.Join(client.ScopesAllowed, " "), "email")
	personal, err := s.userInfoSource.UserInfo(r.Context(), grant.UserID, grant.Region, shareEmail)
	if errors.Is(err, oidc.ErrUserInfoUnavailable) {
		writeUnauthorized(w, "invalid_token", "access token is invalid")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "UserInfo is unavailable")
		return
	}
	resp := openapi.UserInfoResponse{Sub: claims.Subject}
	if shareEmail && personal.Email != "" && personal.EmailVerified {
		address := types.Email(personal.Email)
		verified := true
		resp.Email, resp.EmailVerified = &address, &verified
	}

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

func hasScope(scope, wanted string) bool {
	for _, item := range strings.Fields(scope) {
		if item == wanted {
			return true
		}
	}
	return false
}
