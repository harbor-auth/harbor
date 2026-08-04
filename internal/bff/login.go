package bff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/harbor-auth/harbor/internal/oidc"
)

// WebAuthnService abstracts the webauthn.Service methods needed by LoginHandler.
// This allows the handler to work without importing internal/webauthn directly,
// which would violate the arch boundary (bff must not import webauthn).
type WebAuthnService interface {
	// BeginLogin starts an assertion for a known user. Returns assertion options
	// and an opaque session key to be echoed back via cookie.
	BeginLogin(ctx context.Context, userID []byte) (*protocol.CredentialAssertion, string, error)
	// FinishLogin completes the assertion ceremony. The sessionKey is the opaque
	// key returned by BeginLogin (echoed via cookie). Returns the authenticated
	// user's internal ID and their current recovery_required status on success,
	// so the caller can scope the resulting BFF session correctly instead of
	// defaulting to full access.
	FinishLogin(ctx context.Context, sessionKey string, response *protocol.ParsedCredentialAssertionData) (userID string, recoveryRequired bool, err error)
	// BeginDiscoverableLogin starts a discoverable (passkey/usernameless) assertion
	// ceremony. No user identity is required — the authenticator returns the
	// userHandle in its response. Returns assertion options and a session key.
	BeginDiscoverableLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error)
	// FinishDiscoverableLogin completes a discoverable assertion ceremony. The
	// userHandle from the authenticator response is used to identify the user;
	// no prior user identity is needed. Returns the resolved userID and their
	// current recovery_required status (see FinishLogin).
	FinishDiscoverableLogin(ctx context.Context, sessionKey string, response *protocol.ParsedCredentialAssertionData) (userID string, recoveryRequired bool, err error)
}

// UserResolver looks up a user's WebAuthn user handle ([]byte) from the BFF
// session context. In the initial flow, the user identifies themselves (e.g.,
// by entering their email/username) and the resolver returns their user handle.
//
// For now, this is a simple interface that takes the request and session and
// returns the user handle. Implementations can prompt for user identity or
// use session state.
type UserResolver interface {
	// ResolveUser returns the WebAuthn user handle for the current login attempt.
	// The session provides context (client_id, etc.) and the request may carry
	// user-supplied identity (e.g., email form field).
	ResolveUser(ctx context.Context, r *http.Request, session BFFSessionRecord) ([]byte, error)
}

// ErrUserNotIdentified is returned when the user cannot be identified from the
// request or session state.
var ErrUserNotIdentified = errors.New("bff: user not identified")

// ErrDiscoverable is returned by DiscoverableUserResolver.ResolveUser to signal
// that the login flow should use WebAuthn discoverable credentials (passkey
// autofill). The caller must detect this sentinel and branch to
// BeginDiscoverableLogin rather than BeginLogin.
var ErrDiscoverable = errors.New("bff: discoverable login required")

// DiscoverableUserResolver implements UserResolver for the discoverable
// (passkey/usernameless) login path. Its ResolveUser always returns
// ErrDiscoverable, which causes LoginHandler.BeginLogin to call
// BeginDiscoverableLogin instead of BeginLogin(userID). No user identity is
// required upfront — the authenticator supplies the userHandle in the assertion.
type DiscoverableUserResolver struct{}

// ResolveUser implements UserResolver by always returning ErrDiscoverable,
// signalling that discoverable-credential flow must be used.
func (DiscoverableUserResolver) ResolveUser(_ context.Context, _ *http.Request, _ BFFSessionRecord) ([]byte, error) {
	return nil, ErrDiscoverable
}

// LoginHandler serves the /login endpoint that initiates passkey assertion.
// It reads the BFF session, resolves the user identity, calls BeginAssertion,
// sets the BFF cookie, and returns the assertion options.
type LoginHandler struct {
	sessions             BFFSessionStore
	webauthn             WebAuthnService
	userResolver         UserResolver
	authorizeCompleteURL string
}

// NewLoginHandler creates a handler for the /login endpoint.
// authorizeCompleteURL is the absolute URL of the /authorize/complete endpoint
// on harbor-hot (e.g. "https://auth.example.com/authorize/complete"). It must
// be non-empty in production deployments (M2 fix: avoids relative-URL 404).
func NewLoginHandler(sessions BFFSessionStore, webauthn WebAuthnService, resolver UserResolver, authorizeCompleteURL string) *LoginHandler {
	return &LoginHandler{
		sessions:             sessions,
		webauthn:             webauthn,
		userResolver:         resolver,
		authorizeCompleteURL: authorizeCompleteURL,
	}
}

// BeginLogin handles GET/POST /login?request_id=<id>.
//
// Flow:
//  1. Read request_id from query param
//  2. Look up BFF session (fail if not found/expired)
//  3. Resolve user_id from session state or request
//  4. Call webauthn.BeginLogin
//  5. Set __Host-harbor-bff cookie with request_id
//  6. Return assertion options to browser
func (h *LoginHandler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	requestID := r.URL.Query().Get("request_id")
	if requestID == "" {
		writeLoginError(w, http.StatusBadRequest, "invalid_request", "missing request_id")
		return
	}

	// Look up BFF session
	session, err := h.sessions.Get(r.Context(), requestID)
	if err != nil {
		if errors.Is(err, ErrBFFSessionNotFound) || errors.Is(err, ErrBFFSessionExpired) {
			writeLoginError(w, http.StatusBadRequest, "session_expired", "session not found or expired")
			return
		}
		writeLoginError(w, http.StatusInternalServerError, "server_error", "could not retrieve session")
		return
	}

	// Enforce browser nonce gate (audit finding C3 — session fixation defense).
	// The nonce was minted at /authorize and its hash stored in the session.
	// A request that cannot present the matching cookie did not originate from
	// the browser that started the flow — refuse immediately. Never set the
	// BFF cookie from the URL param (that was the fixation vector).
	if len(session.BrowserNonceHash) == 0 {
		writeLoginError(w, http.StatusBadRequest, "invalid_request", "browser nonce mismatch")
		return
	}
	nonce, nonceErr := ReadBFFNonceCookie(r)
	if nonceErr != nil || !NonceMatches(nonce, session.BrowserNonceHash) {
		writeLoginError(w, http.StatusBadRequest, "invalid_request", "browser nonce mismatch")
		return
	}

	// Resolve the user identity. DiscoverableUserResolver returns ErrDiscoverable
	// to signal that we should skip user resolution and use the discoverable
	// credential flow instead.
	userID, resolveErr := h.userResolver.ResolveUser(r.Context(), r, session)

	var options *protocol.CredentialAssertion
	var sessionKey string
	var beginErr error

	switch {
	case errors.Is(resolveErr, ErrDiscoverable):
		// Discoverable path: authenticator identifies the user.
		options, sessionKey, beginErr = h.webauthn.BeginDiscoverableLogin(r.Context())
	case resolveErr != nil:
		if errors.Is(resolveErr, ErrUserNotIdentified) {
			writeLoginError(w, http.StatusBadRequest, "user_not_identified", "could not identify user")
			return
		}
		writeLoginError(w, http.StatusInternalServerError, "server_error", "could not resolve user")
		return
	default:
		// Known-user path: begin assertion for the resolved user.
		options, sessionKey, beginErr = h.webauthn.BeginLogin(r.Context(), userID)
	}

	if beginErr != nil {
		// Don't leak whether the user exists — collapse to generic error
		writeLoginError(w, http.StatusBadRequest, "invalid_request", "could not begin login")
		return
	}

	// Set the BFF session cookie. The nonce gate above has already proven that
	// this browser originated the flow at /authorize (it holds the matching nonce),
	// so binding requestID (which came from the URL) to the cookie is now safe.
	// Without the nonce gate this was the fixation vector — the gate must precede
	// this call.
	SetBFFCookie(w, requestID, DefaultCookieMaxAge)

	// Set the WebAuthn session key cookie (separate from BFF session cookie).
	setWebAuthnSessionCookie(w, sessionKey)

	// Return assertion options
	writeLoginJSON(w, http.StatusOK, options)
}

// --- Response helpers ---

type loginErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeLoginJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeLoginError(w http.ResponseWriter, status int, code, message string) {
	writeLoginJSON(w, status, loginErrorResponse{Code: code, Message: message})
}

// WebAuthn session cookie for the ceremony (separate from BFF session cookie)
const webauthnSessionCookieName = "harbor_webauthn_session"

func setWebAuthnSessionCookie(w http.ResponseWriter, key string) {
	http.SetCookie(w, &http.Cookie{
		Name:     webauthnSessionCookieName,
		Value:    key,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   300, // 5 min — matches the session store TTL
	})
}

func readWebAuthnSessionCookie(r *http.Request) string {
	cookie, err := r.Cookie(webauthnSessionCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func clearWebAuthnSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     webauthnSessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// FinishLogin handles POST /login/complete.
//
// Flow:
//  1. Read __Host-harbor-bff cookie (CSRF binding)
//  2. Validate request_id matches BFF session
//  3. Parse and validate WebAuthn assertion response from request body
//  4. Call webauthn.FinishLogin
//  5. Write authenticated user_id to BFF session via SetUser
//  6. Redirect to /authorize/complete?request_id=<id>
func (h *LoginHandler) FinishLogin(w http.ResponseWriter, r *http.Request) {
	// Read BFF cookie for CSRF binding
	requestID := ReadBFFCookie(r)
	if requestID == "" {
		writeLoginError(w, http.StatusBadRequest, "invalid_request", "missing BFF session cookie")
		return
	}

	// Read WebAuthn session cookie
	sessionKey := readWebAuthnSessionCookie(r)
	if sessionKey == "" {
		writeLoginError(w, http.StatusBadRequest, "invalid_request", "missing WebAuthn session cookie")
		return
	}

	// Validate BFF session exists
	_, err := h.sessions.Get(r.Context(), requestID)
	if err != nil {
		if errors.Is(err, ErrBFFSessionNotFound) || errors.Is(err, ErrBFFSessionExpired) {
			writeLoginError(w, http.StatusBadRequest, "session_expired", "session not found or expired")
			return
		}
		writeLoginError(w, http.StatusInternalServerError, "server_error", "could not retrieve session")
		return
	}

	// Parse the WebAuthn assertion response from the request body
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		writeLoginError(w, http.StatusBadRequest, "invalid_request", "could not parse assertion response")
		return
	}

	// Delegate to the core logic
	h.FinishLoginWithParsedData(w, r, parsedResponse)
}

// FinishLoginWithParsedData completes the login flow with pre-parsed assertion data.
// This is separated from FinishLogin to enable testing without constructing valid
// WebAuthn assertion payloads.
func (h *LoginHandler) FinishLoginWithParsedData(w http.ResponseWriter, r *http.Request, parsedResponse *protocol.ParsedCredentialAssertionData) {
	requestID := ReadBFFCookie(r)
	sessionKey := readWebAuthnSessionCookie(r)

	// Fetch the BFF session to enforce the browser nonce gate (audit finding C3).
	session, sessErr := h.sessions.Get(r.Context(), requestID)
	if sessErr != nil {
		if errors.Is(sessErr, ErrBFFSessionNotFound) || errors.Is(sessErr, ErrBFFSessionExpired) {
			writeLoginError(w, http.StatusBadRequest, "session_expired", "session not found or expired")
			return
		}
		writeLoginError(w, http.StatusInternalServerError, "server_error", "could not retrieve session")
		return
	}
	if len(session.BrowserNonceHash) == 0 {
		writeLoginError(w, http.StatusBadRequest, "invalid_request", "browser nonce mismatch")
		return
	}
	nonce, nonceErr := ReadBFFNonceCookie(r)
	if nonceErr != nil || !NonceMatches(nonce, session.BrowserNonceHash) {
		writeLoginError(w, http.StatusBadRequest, "invalid_request", "browser nonce mismatch")
		return
	}

	// Branch on the resolver type: discoverable path uses FinishDiscoverableLogin
	// (the authenticator identifies the user via userHandle); known-user path uses
	// FinishLogin as before.
	var userID string
	var recoveryRequired bool
	var err error
	if _, ok := h.userResolver.(DiscoverableUserResolver); ok {
		userID, recoveryRequired, err = h.webauthn.FinishDiscoverableLogin(r.Context(), sessionKey, parsedResponse)
	} else {
		userID, recoveryRequired, err = h.webauthn.FinishLogin(r.Context(), sessionKey, parsedResponse)
	}
	if err != nil {
		// Don't leak details — collapse to generic error
		writeLoginError(w, http.StatusUnauthorized, "authentication_failed", "passkey verification failed")
		return
	}

	// Write the authenticated user_id AND the real recovery_required status to
	// the BFF session in one atomic update. Using the plain SetUser here would
	// leave SessionScope at its Go zero value (""), which never equals
	// SessionScopeFull — every returning user would then fail RequireFullScope
	// on every full-scope-gated route regardless of their actual recovery
	// status. SetUserWithRecoveryStatus stamps SessionScope from the ceremony's
	// own recovery_required lookup instead, matching the scope every other
	// session-issuing path in this package already produces.
	if err := h.sessions.SetUserWithRecoveryStatus(r.Context(), requestID, userID, recoveryRequired); err != nil {
		writeLoginError(w, http.StatusInternalServerError, "server_error", "could not update session")
		return
	}

	// Record the authentication method used (WebAuthn passkey).
	if err := h.sessions.SetAuthMethod(r.Context(), requestID, oidc.AuthMethodWebAuthn); err != nil {
		writeLoginError(w, http.StatusInternalServerError, "server_error", "could not update session")
		return
	}

	// Clear the WebAuthn session cookie (one-time use)
	clearWebAuthnSessionCookie(w)

	// Redirect to the absolute authorize/complete URL (M2 fix: the relative path
	// /authorize/complete resolves against the harbor-mgmt origin, but that
	// endpoint is registered on harbor-hot — the absolute URL is required).
	redirectURL := h.authorizeCompleteURL + "?request_id=" + requestID
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
