package oidcapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/harbor-auth/harbor/internal/gen/openapi"
	"github.com/harbor-auth/harbor/internal/oidc"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

// PostRevoke implements the RFC 7009 Token Revocation endpoint.
//
// Clients must authenticate via Basic auth (client_id:client_secret). Anonymous
// callers receive 401. The endpoint always returns 200 for well-formed,
// authenticated requests — even if the token was invalid, already revoked, or
// not issued to the calling client — to prevent token-fishing attacks (RFC 7009
// §2.2).
//
// Token type handling:
//   - refresh_token: calls Service.RevokeRefreshToken (family revocation)
//   - access_token (JWT): adds JTI to revocation filter + publishes to replicas
//   - If token_type_hint is absent, tries refresh token first, then access token
//
//harbor:invariant INV-REVOKE-ANTI-ENUMERATION
func (s *Server) PostRevoke(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointRevoke, outcome, start) }()

	// Step 1: Authenticate the caller via Basic auth.
	creds, ok := parseBasicAuth(r)
	if !ok {
		recordError(telemetry.EndpointRevoke, "invalid_client")
		writeRevokeUnauthorized(w, "client authentication required")
		return
	}

	// Step 2: Validate that the client exists (service required for revocation).
	if s.svc == nil {
		recordError(telemetry.EndpointRevoke, "invalid_client")
		writeRevokeUnauthorized(w, "revocation not configured")
		return
	}

	// Step 3: Parse the form body.
	// Cap the body before parsing to prevent memory exhaustion (docs/DESIGN.md §6.5).
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	if err := r.ParseForm(); err != nil {
		recordError(telemetry.EndpointRevoke, "invalid_request")
		writeRevokeError(w, "invalid_request", "malformed request body")
		return
	}

	token := r.FormValue("token")
	if token == "" {
		recordError(telemetry.EndpointRevoke, "invalid_request")
		writeRevokeError(w, "invalid_request", "token parameter is required")
		return
	}
	tokenTypeHint := r.FormValue("token_type_hint")

	// Step 4: Revoke the token based on type hint.
	// RFC 7009 §2.1: the hint is advisory; the server SHOULD try both types.
	// We try the hinted type first for efficiency, then fall back to the other.
	switch tokenTypeHint {
	case "access_token":
		s.revokeAccessToken(r, token)
	case "refresh_token":
		s.revokeRefreshToken(r, token, creds.ClientID)
	default:
		// No hint or unknown hint: try refresh token first (more common),
		// then access token. The order follows RFC 7009's guidance that
		// servers should attempt to identify the token.
		s.revokeRefreshToken(r, token, creds.ClientID)
		s.revokeAccessToken(r, token)
	}

	// Step 5: Return 200 with empty body (RFC 7009 §2.2).
	// Anti-enumeration: always 200 regardless of outcome.
	outcome = telemetry.OutcomeSuccess
	writeRevokeSuccess(w)
}

// revokeRefreshToken attempts to revoke a refresh token via the OIDC service.
// Errors are logged but not propagated (anti-enumeration).
func (s *Server) revokeRefreshToken(r *http.Request, token, clientID string) {
	if s.svc == nil {
		return
	}
	// Service.RevokeRefreshToken handles all error cases internally and
	// always returns nil for anti-enumeration. Any errors are logged by
	// the service layer.
	_ = s.svc.RevokeRefreshToken(r.Context(), token, clientID)
}

// revokeAccessToken attempts to revoke an access token (JWT) by extracting
// its JTI and adding it to the revocation filter. This mirrors the emergency
// revocation path in PostAdminRevokeJwt but is triggered by the client.
//
// Errors are logged but not propagated (anti-enumeration).
func (s *Server) revokeAccessToken(r *http.Request, token string) {
	// Parse the JWT to extract claims (particularly jti and exp).
	// If parsing fails, it's not a valid JWT — silent no-op.
	if s.introspector == nil {
		return
	}

	// Use introspector to validate and extract token claims.
	// We pass an empty client ID and IsAdmin=true to bypass cross-client
	// checks — the revocation endpoint already validated client auth.
	req := oidc.IntrospectRequest{
		Token:         token,
		TokenTypeHint: "access_token",
		ClientID:      "", // bypass cross-client check
		IsAdmin:       true,
	}
	resp := s.introspector.Introspect(r.Context(), req)

	// If the token is not active (expired, revoked, malformed), nothing to do.
	// This is the happy path for already-revoked or invalid tokens.
	if !resp.Active {
		return
	}

	// Token is active — revoke it by adding to the filter and publishing.
	if resp.Jti == "" {
		// No JTI claim — can't revoke (shouldn't happen for Harbor-issued tokens).
		return
	}

	// Compute expiry for the revocation entry (garbage collection).
	expiresAt := time.Unix(resp.Exp, 0)

	// Persist to DB if configured (source of truth).
	if s.revoked != nil {
		if _, err := s.revoked.Insert(r.Context(), resp.Jti, "user_request", expiresAt); err != nil {
			// Log but don't fail — anti-enumeration.
			slog.Default().Error("oidcapi: revoke access token insert failed", "error", err)
		}
	}

	// Apply locally first for immediate effect on this replica.
	if s.filter != nil {
		s.filter.Add(resp.Jti)
	}

	// Best-effort cross-replica broadcast.
	if s.publisher != nil {
		if err := s.publisher.Publish(r.Context(), s.revChannel, resp.Jti); err != nil {
			slog.Default().Warn("oidcapi: revoke access token publish failed", "error", err)
		}
	}
}

// writeRevokeSuccess writes an empty 200 response with appropriate headers
// per RFC 7009 §2.2.
func writeRevokeSuccess(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
}

// writeRevokeUnauthorized writes a 401 error for revocation auth failures.
// Uses OAuthError format per RFC 7009.
func writeRevokeUnauthorized(w http.ResponseWriter, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("WWW-Authenticate", `Basic realm="token_revocation"`)
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(openapi.OAuthError{
		Error:            "invalid_client",
		ErrorDescription: description,
	})
}

// writeRevokeError writes a 400 error for malformed revocation requests.
// Uses OAuthError format per RFC 7009.
func writeRevokeError(w http.ResponseWriter, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(openapi.OAuthError{
		Error:            code,
		ErrorDescription: description,
	})
}

