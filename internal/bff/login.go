package bff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
)

// WebAuthnService abstracts the webauthn.Service methods needed by LoginHandler.
// This allows the handler to work without importing internal/webauthn directly,
// which would violate the arch boundary (bff must not import webauthn).
type WebAuthnService interface {
	// BeginLogin starts an assertion for a known user. Returns assertion options
	// and an opaque session key to be echoed back via cookie.
	BeginLogin(ctx context.Context, userID []byte) (*protocol.CredentialAssertion, string, error)
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

// LoginHandler serves the /login endpoint that initiates passkey assertion.
// It reads the BFF session, resolves the user identity, calls BeginAssertion,
// sets the BFF cookie, and returns the assertion options.
type LoginHandler struct {
	sessions     BFFSessionStore
	webauthn     WebAuthnService
	userResolver UserResolver
}

// NewLoginHandler creates a handler for the /login endpoint.
func NewLoginHandler(sessions BFFSessionStore, webauthn WebAuthnService, resolver UserResolver) *LoginHandler {
	return &LoginHandler{
		sessions:     sessions,
		webauthn:     webauthn,
		userResolver: resolver,
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

	// Resolve the user identity
	userID, err := h.userResolver.ResolveUser(r.Context(), r, session)
	if err != nil {
		if errors.Is(err, ErrUserNotIdentified) {
			writeLoginError(w, http.StatusBadRequest, "user_not_identified", "could not identify user")
			return
		}
		writeLoginError(w, http.StatusInternalServerError, "server_error", "could not resolve user")
		return
	}

	// Begin the WebAuthn assertion
	options, sessionKey, err := h.webauthn.BeginLogin(r.Context(), userID)
	if err != nil {
		// Don't leak whether the user exists — collapse to generic error
		writeLoginError(w, http.StatusBadRequest, "invalid_request", "could not begin login")
		return
	}

	// Set the BFF session cookie for CSRF binding
	SetBFFCookie(w, requestID, DefaultCookieMaxAge)

	// Also set the WebAuthn session key cookie (separate from BFF cookie)
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
