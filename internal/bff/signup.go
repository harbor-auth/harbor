package bff

import (
	"errors"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/harbor-auth/harbor/internal/region"
)

// SignupHandler serves the public, pre-session entry points to the passkey
// signup journey: the privacy promise + region picker (GET /signup) and the
// first-passkey ceremony page (GET /signup/passkey). Unlike DashboardHandler,
// these routes run BEFORE any BFF session cookie exists, so they carry no
// caller identity and no session-scope gate — the pages themselves only ever
// render static copy plus the region list; all state-changing work happens
// client-side against the existing POST /enroll and POST /webauthn/register/*
// endpoints (docs/DESIGN.md §9, §11.1).
type SignupHandler struct {
	tmpl   *template.Template
	logger *slog.Logger
}

// NewSignupHandler returns a handler ready to serve the public signup pages.
// tmpl must be a parsed *html/template.Template containing "signup.html" and
// "signup_passkey.html" (see web/templates/).
func NewSignupHandler(tmpl *template.Template, logger *slog.Logger) (*SignupHandler, error) {
	if tmpl == nil {
		return nil, errors.New("bff: signup templates are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &SignupHandler{tmpl: tmpl, logger: logger}, nil
}

// Routes registers the public signup routes on mux. Both are plain GETs with
// no side effects, so — unlike the dashboard's mutating routes — neither needs
// RequireFullScope or CSRF middleware; the state-changing requests they drive
// (POST /enroll, POST /webauthn/register/begin|finish) already carry their
// own PreSessionCSRF + rate-limit + body-size defenses at the routing layer.
func (h *SignupHandler) Routes(mux *http.ServeMux) {
	mux.Handle("GET /signup", http.HandlerFunc(h.GetSignup))
	mux.Handle("GET /signup/passkey", http.HandlerFunc(h.GetSignupPasskey))
}

// signupRegionOption is one option rendered in the region picker.
type signupRegionOption struct {
	Code  string
	Label string
}

// signupRegionCandidates is the ordered list of region codes the picker may
// offer. It is deliberately just a candidate list: allowedSignupRegions below
// filters it through region.Parse, so a code retired from region.Parse
// silently disappears from the picker instead of offering a region the
// backend would reject.
var signupRegionCandidates = []signupRegionOption{
	{Code: "EU", Label: "European Union"},
	{Code: "US", Label: "United States"},
	{Code: "APAC", Label: "Asia-Pacific"},
}

// allowedSignupRegions returns the subset of signupRegionCandidates that
// region.Parse actually accepts, in candidate order.
func allowedSignupRegions() []signupRegionOption {
	out := make([]signupRegionOption, 0, len(signupRegionCandidates))
	for _, c := range signupRegionCandidates {
		if _, err := region.Parse(c.Code); err != nil {
			continue
		}
		out = append(out, c)
	}
	return out
}

// signupData is the template data for GET /signup.
type signupData struct {
	Regions []signupRegionOption
}

// GetSignup renders the privacy promise and region picker. The form on this
// page starts enrollment by POSTing JSON to the existing POST /enroll (task
// 1's PreSessionCSRF-protected front door), then navigates to
// GET /signup/passkey once an enrollment session cookie has been set.
func (h *SignupHandler) GetSignup(w http.ResponseWriter, r *http.Request) {
	h.renderTemplate(w, r, "signup.html", signupData{Regions: allowedSignupRegions()})
}

// GetSignupPasskey renders the first-passkey ceremony page. Its script drives
// navigator.credentials.create() against POST /webauthn/register/begin and
// POST /webauthn/register/finish, relying entirely on the HttpOnly
// harbor_enrollment_session cookie set by POST /enroll to identify the
// in-progress enrollment — there is deliberately no user_id or email
// parameter anywhere on this page or in the requests it issues (docs/DESIGN.md
// §9: a client-supplied user_id would be an IDOR).
func (h *SignupHandler) GetSignupPasskey(w http.ResponseWriter, r *http.Request) {
	h.renderTemplate(w, r, "signup_passkey.html", nil)
}

// renderTemplate executes a named template with data. On error it logs and
// returns a 500 — it never leaks template internals.
func (h *SignupHandler) renderTemplate(w http.ResponseWriter, r *http.Request, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, name, data); err != nil {
		h.logger.ErrorContext(r.Context(), "bff: signup: template render failed",
			"template", name, "error", err)
	}
}
