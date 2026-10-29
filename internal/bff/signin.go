package bff

import (
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// SigninHandler serves the public GET /signin entry point: a discoverable-
// credential (passkey) sign-in page with no identifier field anywhere.
//
// The actual authentication ceremony is driven entirely by the existing,
// unmodified GET /login and POST /login/complete endpoints (wired with
// DiscoverableUserResolver — see cmd/harbor-mgmt/main.go). Plain sign-in creates
// a personal session and browser nonce. When /authorize supplies request_id,
// it instead resumes that browser-bound RP transaction and completes it through
// /authorize/complete after the passkey ceremony.
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
	if requestID := r.URL.Query().Get("request_id"); requestID != "" {
		h.serveAuthorizationSignin(w, r, requestID)
		return
	}
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

// /authorize has already created the RP transaction and bound it to a browser
// nonce. Replacing it with a personal session discards the RP callback/PKCE
// state. Resume only after proving this browser owns that live transaction.
func (h *SigninHandler) serveAuthorizationSignin(w http.ResponseWriter, r *http.Request, requestID string) {
	session, err := h.sessions.Get(r.Context(), requestID)
	nonce, nonceErr := ReadBFFNonceCookie(r)
	if err != nil || nonceErr != nil || session.ClientID == "" || session.RedirectURI == "" ||
		!session.ExpiresAt.After(time.Now()) || len(session.BrowserNonceHash) == 0 ||
		!NonceMatches(nonce, session.BrowserNonceHash) {
		http.Error(w, "invalid or expired sign-in request; restart sign-in from the app", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	data := signinPageData{
		RequestID: requestID,
		ReturnTo:  "/authorize/complete?" + url.Values{"request_id": {requestID}}.Encode(),
	}
	if err := h.tmpl.ExecuteTemplate(w, "signin.html", data); err != nil {
		h.logger.ErrorContext(r.Context(), "bff: render authorization signin template", "error", err)
	}
}
