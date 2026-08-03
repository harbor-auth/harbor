package bff

import (
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"time"
)

// SigninHandler serves the public GET /signin entry point: a discoverable-
// credential (passkey) sign-in page with no identifier field anywhere.
//
// The actual authentication ceremony is driven entirely by the existing,
// unmodified GET /login and POST /login/complete endpoints (wired with
// DiscoverableUserResolver — see cmd/harbor-mgmt/main.go). This handler's only
// job is to establish the one-time BFF session and browser-nonce binding those
// endpoints require, exactly as internal/oidcapi's authorizeWithBFFSession
// does for the OIDC flow, minus any OIDC-specific fields (ClientID,
// RedirectURI, Scope, ...) that a plain sign-in has no use for.
type SigninHandler struct {
	sessions          BFFSessionStore
	tmpl              *template.Template
	sessionTTL        time.Duration
	returnToAllowlist []string
	logger            *slog.Logger
}

// NewSigninHandler returns a handler ready to serve GET /signin. tmpl must
// contain a "signin.html" named template (see web/templates/signin.html).
// returnToAllowlist is the set of hosts (e.g. the Harbor Cloud marketing site
// and demo) ValidateReturnTo accepts for an absolute return_to; a same-origin
// relative path is always accepted regardless of this list.
func NewSigninHandler(sessions BFFSessionStore, tmpl *template.Template, sessionTTL time.Duration, returnToAllowlist []string, logger *slog.Logger) (*SigninHandler, error) {
	if sessions == nil {
		return nil, errors.New("bff: signin session store is required")
	}
	if tmpl == nil {
		return nil, errors.New("bff: signin template is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &SigninHandler{
		sessions:          sessions,
		tmpl:              tmpl,
		sessionTTL:        sessionTTL,
		returnToAllowlist: returnToAllowlist,
		logger:            logger,
	}, nil
}

// signinPageData is the html/template data for signin.html. RequestID is a
// fresh CSPRNG identifier and ReturnTo has already passed ValidateReturnTo, so
// both are safe to interpolate — html/template additionally applies contextual
// JS-string escaping wherever the template embeds them.
type signinPageData struct {
	RequestID string
	ReturnTo  string
}

// ServeSignin handles GET /signin?return_to=<url>.
//
// Flow:
//  1. Validate return_to against the configured allowlist (task 1's
//     ValidateReturnTo) — an unrecognized value silently falls back to the
//     same-origin default and is never echoed back to the client.
//  2. Create a fresh BFF session (no ClientID/RedirectURI — this is not an
//     OIDC ceremony) with a browser-nonce hash, mirroring /authorize.
//  3. Set the browser nonce cookie before rendering, so the binding is
//     established before the page's script ever calls GET /login.
//  4. Render signin.html with the request_id and validated return_to
//     embedded for its script to use against the unmodified GET /login and
//     POST /login/complete endpoints.
func (h *SigninHandler) ServeSignin(w http.ResponseWriter, r *http.Request) {
	returnTo, _ := ValidateReturnTo(r.URL.Query().Get("return_to"), h.returnToAllowlist)

	requestID, err := NewRequestID()
	if err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}
	nonce, err := NewBrowserNonce()
	if err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}

	record := BFFSessionRecord{
		RequestID:        requestID,
		BrowserNonceHash: HashNonce(nonce),
		ExpiresAt:        time.Now().Add(h.sessionTTL),
	}
	if err := h.sessions.Create(r.Context(), record); err != nil {
		h.logger.ErrorContext(r.Context(), "bff: signin: create session failed", "error", err)
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}

	SetBFFNonceCookie(w, nonce, h.sessionTTL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := signinPageData{RequestID: requestID, ReturnTo: returnTo}
	if err := h.tmpl.ExecuteTemplate(w, "signin.html", data); err != nil {
		h.logger.ErrorContext(r.Context(), "bff: signin: template render failed", "error", err)
	}
}
