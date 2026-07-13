package oidcapi

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/harbor/harbor/internal/gen/openapi"
	"github.com/harbor/harbor/internal/oidc"
)

// PostToken serves the OIDC Token endpoint (POST /token). It parses the
// form-encoded body, delegates the exchange to the pure-core-backed service, and
// returns JSON: 200 with the tokens on success, or a 400/401 OAuth error body
// (RFC 6749 §5.2). All responses set Cache-Control: no-store (docs/DESIGN.md
// §11.7).
func (s *Server) PostToken(w http.ResponseWriter, r *http.Request) {
	// Cap the request body before parsing so a flooded /token can't exhaust
	// memory (docs/DESIGN.md §6.5). 64KB is far beyond any legitimate form.
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, &oidc.TokenError{
			Code:        oidc.ErrCodeInvalidRequest,
			Description: "malformed request body",
			Status:      http.StatusBadRequest,
		})
		return
	}

	req := oidc.TokenRequest{
		GrantType:    r.PostFormValue("grant_type"),
		Code:         r.PostFormValue("code"),
		RedirectURI:  r.PostFormValue("redirect_uri"),
		ClientID:     r.PostFormValue("client_id"),
		CodeVerifier: r.PostFormValue("code_verifier"),
		RefreshToken: r.PostFormValue("refresh_token"),
		// NOTE: RFC 6749 §6 allows a client to request a narrower scope on a
		// refresh_token grant via the `scope` form parameter. Harbor currently
		// does not parse this field — TokenRequest has no Scope field — so any
		// client-supplied scope on a refresh request is silently ignored and the
		// full frozen grant scopes are always returned. This is a known
		// intentional omission documented in service.go Refresh() Step B.
	}

	var tokens *oidc.IssuedTokens
	var terr *oidc.TokenError
	if req.GrantType == "refresh_token" {
		tokens, terr = s.svc.Refresh(r.Context(), req)
	} else {
		tokens, terr = s.svc.Token(r.Context(), req)
	}
	if terr != nil {
		writeOAuthError(w, terr)
		return
	}

	writeTokenResponse(w, tokens)
}

// writeTokenResponse emits the 200 JSON token response with no-store caching.
func writeTokenResponse(w http.ResponseWriter, t *oidc.IssuedTokens) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	resp := openapi.TokenResponse{
		AccessToken: t.AccessToken,
		TokenType:   t.TokenType,
		ExpiresIn:   t.ExpiresIn,
		IdToken:     t.IDToken,
		Scope:       t.Scope,
	}
	if t.RefreshToken != "" {
		resp.RefreshToken = &t.RefreshToken
		v := t.RefreshExpiresIn
		resp.RefreshExpiresIn = &v
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// WriteHeader(200) was already sent — status cannot be changed.
		// Log the write failure (usually a client TCP disconnect) for observability.
		slog.Default().Error("oidcapi: failed to encode token response", "error", err)
	}
}

// writeOAuthError emits the OAuth error body at the error's HTTP status, with
// no-store caching. The description is generic and PII-free (docs/DESIGN.md
// §11.7 — no account/client existence disclosure).
func writeOAuthError(w http.ResponseWriter, e *oidc.TokenError) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	// WWW-Authenticate: Basic is required by RFC 6749 §5.2 when the client
	// fails to authenticate using HTTP Basic auth (invalid_client). Currently
	// no code path returns ErrCodeInvalidClient (Harbor uses PKCE public-client
	// flow, not client_secret_basic). This branch is retained as a placeholder
	// for future client authentication support.
	// NOTE: RFC 6750 §3 and RFC 7235 require the realm parameter
	// (e.g. `Basic realm="Harbor"`) for a strictly conformant response, and
	// RFC 6749 §5.2 requires error= and error_description= parameters. The
	// bare `Basic` header emitted here is acceptable only while this branch is
	// dead (no real caller). Add realm + error params when wiring real
	// client_secret_basic support.
	if e.Code == oidc.ErrCodeInvalidClient {
		w.Header().Set("WWW-Authenticate", "Basic")
	}
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(openapi.OAuthError{
		Error:            e.Code,
		ErrorDescription: e.Description,
	})
}
