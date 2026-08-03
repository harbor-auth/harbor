// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// genericLoginError is returned for every failure path below. The specific
// reason (state mismatch, expired session, IdP error, token-exchange
// failure, nonce mismatch, ...) is deliberately never echoed to the
// client: distinguishing failure modes in the response gives an attacker a
// free oracle for probing the flow.
const genericLoginError = "login failed"

// CallbackHandler completes the Authorization Code + PKCE flow started by
// LoginHandler.
type CallbackHandler struct {
	TokenEndpoint string
	ClientID      string
	// RedirectURI must be byte-identical to the value LoginHandler sent as
	// redirect_uri — the token endpoint checks this per RFC 6749 §4.1.3.
	RedirectURI string
	// Issuer is the configured issuer identifier, checked against the ID
	// token's iss claim.
	Issuer     string
	Sessions   *sessionStore
	HTTPClient *http.Client
}

func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		http.Error(w, genericLoginError, http.StatusBadRequest)
		return
	}

	// takePending deletes on read: a given pre-auth session (and the state
	// it carries) can be redeemed at most once. A replayed callback for an
	// already-consumed session is rejected exactly like an unknown one.
	pending, ok := h.Sessions.takePending(cookie.Value)
	if !ok {
		http.Error(w, genericLoginError, http.StatusBadRequest)
		return
	}

	if idpErr := r.URL.Query().Get("error"); idpErr != "" {
		http.Error(w, genericLoginError, http.StatusBadRequest)
		return
	}

	// Reject any request whose state does not match the server-side
	// session before doing anything else with the request. Constant-time
	// comparison avoids leaking a timing side-channel on the correct
	// prefix of a guessed state value.
	state := r.URL.Query().Get("state")
	if state == "" || subtle.ConstantTimeCompare([]byte(state), []byte(pending.State)) != 1 {
		http.Error(w, genericLoginError, http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, genericLoginError, http.StatusBadRequest)
		return
	}

	tokens, err := h.exchangeCode(r.Context(), code, pending.CodeVerifier)
	if err != nil {
		http.Error(w, genericLoginError, http.StatusBadGateway)
		return
	}

	claims, err := decodeIDTokenClaims(tokens.IDToken)
	if err != nil {
		http.Error(w, genericLoginError, http.StatusBadGateway)
		return
	}

	// Nonce binds the ID token to *this* authorization request, so a token
	// obtained via a different (or replayed) flow can't be substituted in.
	if claims.Nonce == "" || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(pending.Nonce)) != 1 {
		http.Error(w, genericLoginError, http.StatusBadGateway)
		return
	}
	if claims.Issuer != h.Issuer {
		http.Error(w, genericLoginError, http.StatusBadGateway)
		return
	}
	if !audienceContains(claims.Audience, h.ClientID) {
		http.Error(w, genericLoginError, http.StatusBadGateway)
		return
	}
	if claims.Expiry != 0 && time.Now().Unix() >= claims.Expiry {
		http.Error(w, genericLoginError, http.StatusBadGateway)
		return
	}

	newSessionID, err := randomToken(32)
	if err != nil {
		http.Error(w, genericLoginError, http.StatusInternalServerError)
		return
	}
	// Rotate the session: the pre-auth identifier (already consumed by
	// takePending above) is never reused post-login. Minting a fresh one
	// here defeats session fixation — an attacker who planted the pre-auth
	// cookie in a victim's browser ends up with a dead identifier, and has
	// no way to learn the post-login one issued below.
	h.Sessions.putSession(newSessionID, Session{
		Subject:  claims.Subject,
		IssuedAt: time.Now(),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    newSessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	fmt.Fprintf(w, "signed in as %s\n", claims.Subject)
}

// tokenResponse is the subset of a Token Endpoint response (RFC 6749 §5.1,
// OpenID Connect Core 1.0 §3.1.3.3) this example needs.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

func (h *CallbackHandler) exchangeCode(ctx context.Context, code, verifier string) (tokenResponse, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {h.RedirectURI},
		"client_id":     {h.ClientID},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.HTTPClient.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return tokenResponse{}, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var tr tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return tokenResponse{}, fmt.Errorf("decoding token response: %w", err)
	}
	if tr.IDToken == "" {
		return tokenResponse{}, fmt.Errorf("token response missing id_token")
	}
	return tr, nil
}

// idTokenClaims is the subset of ID token claims (OpenID Connect Core 1.0
// §2) this example needs.
type idTokenClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience any    `json:"aud"`
	Nonce    string `json:"nonce"`
	Expiry   int64  `json:"exp"`
}

// decodeIDTokenClaims extracts the ID token's claims WITHOUT verifying its
// signature.
//
// That is sufficient for what this example demonstrates — the RP-owned
// state/nonce/PKCE flow — but is NOT sufficient for production use. A real
// RP must verify the ID token's signature against the issuer's published
// JWKS (see ../../docs/SECURITY.md, "JWKS rotation") before trusting any
// claim, including the ones this handler checks above.
func decodeIDTokenClaims(idToken string) (idTokenClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return idTokenClaims{}, fmt.Errorf("malformed ID token: expected 3 dot-separated parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return idTokenClaims{}, fmt.Errorf("malformed ID token payload: %w", err)
	}
	var claims idTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return idTokenClaims{}, fmt.Errorf("malformed ID token claims: %w", err)
	}
	return claims, nil
}

// audienceContains reports whether aud — a JSON "aud" claim, which per RFC
// 7519 §4.1.3 is either a single string or an array of strings — contains
// clientID.
func audienceContains(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}
