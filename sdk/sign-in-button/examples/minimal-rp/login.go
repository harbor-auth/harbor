// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"time"
)

// LoginHandler initiates the OIDC Authorization Code flow with PKCE (S256).
// It never accepts state, nonce, redirect_uri, client_id, or any other flow
// parameter from the incoming request — every one of them is either minted
// fresh or pulled from pre-configured, startup-time fields, so a
// maliciously crafted link to this endpoint cannot smuggle attacker-chosen
// values into the flow.
type LoginHandler struct {
	// AuthorizeURL is the identity provider's authorization endpoint, as
	// discovered from OIDC discovery at startup (see main.go).
	AuthorizeURL string
	// ClientID is this RP's registered OIDC client_id.
	ClientID string
	// RedirectURI is the single, pre-configured, allowlisted callback URL
	// registered with the identity provider. It is a startup-configuration
	// value — NEVER derived from the incoming request (query string, Host
	// header, Referer, or otherwise). An attacker-controlled redirect_uri
	// is an open-redirect / authorization-code-theft primitive; the only
	// safe source for it is server-side configuration.
	RedirectURI string
	// Sessions stores the pending authorization request server-side, keyed
	// by the opaque cookie minted below.
	Sessions *sessionStore
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	state, err := randomToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := randomToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// RFC 7636 §4.1 requires a code_verifier with 43-128 characters of
	// base64url output; 64 random bytes encodes to 86 characters.
	verifier, err := randomToken(64)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sessionID, err := randomToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.Sessions.putPending(sessionID, PendingAuth{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		CreatedAt:    time.Now(),
	})

	// HttpOnly: client-side JS can never read the session identifier, and
	// therefore never the state/nonce/code_verifier it unlocks.
	// Secure+SameSite=Lax: never sent over plaintext HTTP or from a
	// cross-site context.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   int(pendingAuthTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {h.ClientID},
		"redirect_uri":          {h.RedirectURI},
		"scope":                 {"openid profile"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {s256Challenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, h.AuthorizeURL+"?"+q.Encode(), http.StatusFound)
}

// randomToken returns a CSPRNG-generated, base64url-encoded (unpadded)
// token built from n random bytes.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// s256Challenge derives a PKCE code_challenge from verifier per RFC 7636
// §4.2: BASE64URL-ENCODE(SHA256(ASCII(verifier))).
func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
