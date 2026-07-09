package oidcapi

import (
	"encoding/json"
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
	}

	tokens, terr := s.svc.Token(r.Context(), req)
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
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(openapi.TokenResponse{
		AccessToken: t.AccessToken,
		TokenType:   t.TokenType,
		ExpiresIn:   t.ExpiresIn,
		IdToken:     t.IDToken,
		Scope:       t.Scope,
	})
}

// writeOAuthError emits the OAuth error body at the error's HTTP status, with
// no-store caching. The description is generic and PII-free (docs/DESIGN.md
// §11.7 — no account/client existence disclosure).
func writeOAuthError(w http.ResponseWriter, e *oidc.TokenError) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if e.Code == oidc.ErrCodeInvalidClient {
		w.Header().Set("WWW-Authenticate", "Basic")
	}
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(openapi.OAuthError{
		Error:            e.Code,
		ErrorDescription: e.Description,
	})
}
