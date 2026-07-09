package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
)

// sessionCookieName carries the opaque, server-side ceremony session key between
// the Begin and Finish steps. It is NOT a bearer token — just a lookup key —
// but is still HttpOnly/Secure/SameSite to keep it off the client and bound to
// same-site requests (docs/DESIGN.md §9).
const sessionCookieName = "harbor_webauthn_session"

// Handler serves the passkey ceremony endpoints. Keep it thin: it parses the
// request, delegates to Service, and shapes the response.
type Handler struct {
	svc *Service
	// allowInsecureUserID enables the DEV-ONLY path that reads the WebAuthn user
	// handle from a client-supplied `user_id` query param. It MUST be false in
	// production — see userIDFromRequest (docs/DESIGN.md §9).
	allowInsecureUserID bool
}

// NewHandler returns a Handler for the given Service. allowInsecureUserID gates
// the dev-only client-supplied user_id path and must be false in production.
func NewHandler(svc *Service, allowInsecureUserID bool) *Handler {
	return &Handler{svc: svc, allowInsecureUserID: allowInsecureUserID}
}

// RegisterRoutes mounts the four ceremony endpoints on mux:
//
//	POST /webauthn/register/begin
//	POST /webauthn/register/finish
//	POST /webauthn/login/begin
//	POST /webauthn/login/finish
//
// allowInsecureUserID gates the dev-only user_id path (must be false in prod).
func RegisterRoutes(mux *http.ServeMux, svc *Service, allowInsecureUserID bool) {
	h := NewHandler(svc, allowInsecureUserID)
	mux.HandleFunc("POST /webauthn/register/begin", h.BeginRegistration)
	mux.HandleFunc("POST /webauthn/register/finish", h.FinishRegistration)
	mux.HandleFunc("POST /webauthn/login/begin", h.BeginLogin)
	mux.HandleFunc("POST /webauthn/login/finish", h.FinishLogin)
}

// BeginRegistration handles POST /webauthn/register/begin.
func (h *Handler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.userIDFromRequest(w, r)
	if !ok {
		return
	}
	options, key, err := h.svc.BeginRegistration(r.Context(), userID)
	if err != nil {
		writeError(w, err)
		return
	}
	setSessionCookie(w, key)
	writeJSON(w, http.StatusOK, options)
}

// FinishRegistration handles POST /webauthn/register/finish.
func (h *Handler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.userIDFromRequest(w, r)
	if !ok {
		return
	}
	key, err := readSessionCookie(r)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, "session_expired", "missing or invalid session")
		return
	}
	if _, err := h.svc.FinishRegistration(r.Context(), userID, key, r.Body); err != nil {
		writeError(w, err)
		return
	}
	clearSessionCookie(w)
	writeJSON(w, http.StatusOK, statusOK{Status: "registered"})
}

// BeginLogin handles POST /webauthn/login/begin.
func (h *Handler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.userIDFromRequest(w, r)
	if !ok {
		return
	}
	options, key, err := h.svc.BeginLogin(r.Context(), userID)
	if err != nil {
		writeError(w, err)
		return
	}
	setSessionCookie(w, key)
	writeJSON(w, http.StatusOK, options)
}

// FinishLogin handles POST /webauthn/login/finish.
func (h *Handler) FinishLogin(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.userIDFromRequest(w, r)
	if !ok {
		return
	}
	key, err := readSessionCookie(r)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, "session_expired", "missing or invalid session")
		return
	}
	if _, err := h.svc.FinishLogin(r.Context(), userID, key, r.Body); err != nil {
		writeError(w, err)
		return
	}
	clearSessionCookie(w)
	writeJSON(w, http.StatusOK, statusOK{Status: "authenticated"})
}

// userIDFromRequest extracts the WebAuthn user handle.
//
// SCAFFOLD: the identity is read from the base64url `user_id` query parameter,
// which lets ANY caller drive a ceremony as ANY user — an IDOR. In production
// the identity MUST come from the authenticated dashboard session (the signed-in
// subject), never from a client-supplied value. That path is therefore gated
// behind allowInsecureUserID: when it is false (the default / production) we
// refuse the request with 501 rather than trust the query param. This is a
// deliberate placeholder until the BFF session middleware lands
// (docs/DESIGN.md §9). On failure it writes the response and returns ok=false.
func (h *Handler) userIDFromRequest(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if !h.allowInsecureUserID {
		writeErrorCode(w, http.StatusNotImplemented, "not_implemented",
			"passkey ceremonies require an authenticated session")
		return nil, false
	}
	raw := r.URL.Query().Get("user_id")
	if raw == "" {
		writeErrorCode(w, http.StatusBadRequest, "invalid_request", "missing user_id")
		return nil, false
	}
	userID, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(userID) == 0 {
		writeErrorCode(w, http.StatusBadRequest, "invalid_request", "invalid user_id encoding")
		return nil, false
	}
	return userID, true
}

// --- response helpers -------------------------------------------------------

type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type statusOK struct {
	Status string `json:"status"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErrorCode(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Code: code, Message: message})
}

// writeError maps a service error to a status + PII-free code (docs/DESIGN.md
// §6.5). Unknown errors collapse to a generic 500 so we never leak internals.
func writeError(w http.ResponseWriter, err error) {
	switch {
	// NOTE: ErrUserNotFound is deliberately NOT given its own response. A distinct
	// "user not found" status/code would let an attacker enumerate valid user
	// handles, so it collapses into the generic invalid_request below — an unknown
	// user is indistinguishable from a malformed ceremony (docs/DESIGN.md §6.5).
	case errors.Is(err, ErrSessionNotFound):
		writeErrorCode(w, http.StatusBadRequest, "session_expired", "ceremony session not found or expired")
	case errors.Is(err, ErrClonedAuthenticator):
		writeErrorCode(w, http.StatusUnauthorized, "cloned_authenticator", "authenticator failed clone detection")
	default:
		// Parse/validation failures from the protocol layer and any other error.
		writeErrorCode(w, http.StatusBadRequest, "invalid_request", "could not complete the WebAuthn ceremony")
	}
}

// --- session cookie helpers -------------------------------------------------

func setSessionCookie(w http.ResponseWriter, key string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    key,
		Path:     "/webauthn",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   300, // 5 min — matches the session store TTL.
	})
}

func readSessionCookie(r *http.Request) (string, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", err
	}
	return c.Value, nil
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/webauthn",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
