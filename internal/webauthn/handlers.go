package webauthn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// sessionCookieName carries the opaque, server-side ceremony session key between
// the Begin and Finish steps. It is NOT a bearer token — just a lookup key —
// but is still HttpOnly/Secure/SameSite to keep it off the client and bound to
// same-site requests (docs/DESIGN.md §9).
const sessionCookieName = "harbor_webauthn_session"

// EnrollmentSessionStore resolves the user handle from the enrollment session
// cookie set by POST /enroll. It is injected from internal/mgmtapi so this
// package stays decoupled from the enrollment implementation.
type EnrollmentSessionStore interface {
	UserHandle(ctx context.Context, key string) ([]byte, error)
}

// enrollmentCookieName is the cookie carrying the enrollment session key. It
// MUST match mgmtapi.EnrollmentSessionCookieName — the packages are decoupled,
// so the value is duplicated and kept in sync deliberately.
const enrollmentCookieName = "harbor_enrollment_session"

// Handler serves the passkey ceremony endpoints. Keep it thin: it parses the
// request, delegates to Service, and shapes the response.
type Handler struct {
	svc *Service
	// enrollmentSessions resolves the WebAuthn user handle from the enrollment
	// session cookie set by POST /enroll — the ONLY supported way to drive a
	// ceremony (§11.1). When nil (or unresolved), every ceremony is refused with
	// 501: Harbor deliberately has no client-supplied user_id seam, which would
	// be an IDOR (docs/DESIGN.md §9).
	enrollmentSessions EnrollmentSessionStore
}

// NewHandler returns a Handler for the given Service. Attach an enrollment
// session store with WithEnrollmentSessions so ceremonies can resolve the user
// handle from the enrollment cookie; without one every ceremony returns 501.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// WithEnrollmentSessions attaches the enrollment session store so registration
// ceremonies can read the user handle from the enrollment cookie (set by POST
// /enroll) instead of requiring the insecure query param. Returns h for chaining.
func (h *Handler) WithEnrollmentSessions(store EnrollmentSessionStore) *Handler {
	h.enrollmentSessions = store
	return h
}

// RegisterRoutes mounts the four ceremony endpoints on mux using a fresh Handler
// with no enrollment session store — every ceremony is refused with 501 until
// WithEnrollmentSessions is attached. Prefer (*Handler).RegisterRoutes when you
// need to wire enrollment sessions (the production path).
func RegisterRoutes(mux *http.ServeMux, svc *Service) {
	NewHandler(svc).RegisterRoutes(mux)
}

// RegisterRoutes mounts the four ceremony endpoints on mux:
//
//	POST /webauthn/register/begin
//	POST /webauthn/register/finish
//	POST /webauthn/login/begin
//	POST /webauthn/login/finish
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
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

// userIDFromRequest extracts the WebAuthn user handle for a ceremony from the
// enrollment session cookie (harbor_enrollment_session) set by POST /enroll —
// the only supported path (§11.1). There is deliberately NO client-supplied
// user_id: letting a caller name the ceremony's user is an IDOR (docs/DESIGN.md
// §9). When no valid enrollment session is present the request is refused with
// 501 Not Implemented, since no other authenticated seam exists yet.
//
// On failure it writes the response and returns ok=false.
func (h *Handler) userIDFromRequest(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if h.enrollmentSessions != nil {
		if c, err := r.Cookie(enrollmentCookieName); err == nil && c.Value != "" {
			userID, err := h.enrollmentSessions.UserHandle(r.Context(), c.Value)
			if err == nil && len(userID) > 0 {
				return userID, true
			}
		}
	}
	writeErrorCode(w, http.StatusNotImplemented, "not_implemented",
		"passkey ceremonies require an authenticated session")
	return nil, false
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
