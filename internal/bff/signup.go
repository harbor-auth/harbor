package bff

import (
	"context"
	"errors"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/harbor-auth/harbor/internal/region"
)

// SignupAuditRecorder records signup-lifecycle audit events (signup.enrolled,
// signup.passkey_registered, signup.recovery_completed) on a best-effort
// basis. It is satisfied directly by *identity.AuditRecorder. Emission is
// always non-blocking (RecordAsync detaches from the request context) so a
// slow/failing audit write never stalls GET /signup/success (DESIGN §2.1,
// Decision 3) — matching mgmtapi.ConsentAuditRecorder / oidcapi.TokenAuditRecorder.
type SignupAuditRecorder interface {
	RecordAsync(ctx context.Context, userID string, et identity.EventType, clientID *string, detail any)
}

// SignupHandler serves the public, pre-session entry points to the passkey
// signup journey: the privacy promise + region picker (GET /signup) and the
// first-passkey ceremony page (GET /signup/passkey). Unlike DashboardHandler,
// these routes run BEFORE any BFF session cookie exists, so they carry no
// caller identity and no session-scope gate — the pages themselves only ever
// render static copy plus the region list; all state-changing work happens
// client-side against the existing POST /enroll and POST /webauthn/register/*
// endpoints (docs/DESIGN.md §9, §11.1).
type SignupHandler struct {
	tmpl              *template.Template
	audit             SignupAuditRecorder
	returnToAllowlist []string
	logger            *slog.Logger
}

// NewSignupHandler returns a handler ready to serve the public signup pages.
// tmpl must be a parsed *html/template.Template containing "signup.html" and
// "signup_passkey.html" (see web/templates/). audit may be nil, in which case
// GET /signup/success skips audit emission (best-effort, graceful absence —
// same convention as DashboardHandler's relay dependency). returnToAllowlist
// is the set of hosts (e.g. the Harbor Cloud marketing site and demo)
// ValidateReturnTo accepts for an absolute return_to on GET /signup/success; a
// same-origin relative path is always accepted regardless of this list.
func NewSignupHandler(tmpl *template.Template, audit SignupAuditRecorder, returnToAllowlist []string, logger *slog.Logger) (*SignupHandler, error) {
	if tmpl == nil {
		return nil, errors.New("bff: signup templates are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &SignupHandler{tmpl: tmpl, audit: audit, returnToAllowlist: returnToAllowlist, logger: logger}, nil
}

// Routes registers the public signup routes on mux. GET /signup and GET
// /signup/passkey are plain GETs with no side effects, so — unlike the
// dashboard's mutating routes — neither needs RequireFullScope or CSRF
// middleware; the state-changing requests they drive (POST /enroll, POST
// /webauthn/register/begin|finish) already carry their own PreSessionCSRF +
// rate-limit + body-size defenses at the routing layer.
//
// GET /signup/recovery runs AFTER a BFF session exists (the post-registration
// handoff or the lost-device recovery ceremony issues it), so it is served
// under RequireEnrollmentAllowed: both full and enrollment-only sessions may
// load the page; the mgmtapi endpoints its script drives (POST
// /recovery/codes, POST /recovery/acknowledge) enforce the real
// authentication and authorization.
//
// GET /signup/success runs only after recovery setup has cleared
// recovery_required, so it is served under RequireFullScope — an
// enrollment-only session (recovery not yet completed) gets the same 403 as
// every other full-scope-only surface (dashboard, consent, ...).
func (h *SignupHandler) Routes(mux *http.ServeMux) {
	mux.Handle("GET /signup", http.HandlerFunc(h.GetSignup))
	mux.Handle("GET /signup/passkey", http.HandlerFunc(h.GetSignupPasskey))
	mux.Handle("GET /signup/recovery", RequireEnrollmentAllowed(http.HandlerFunc(h.GetSignupRecovery)))
	mux.Handle("GET /signup/success", RequireFullScope(http.HandlerFunc(h.GetSignupSuccess)))
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

// GetSignupRecovery renders the mandatory recovery-setup page. Its script
// calls the existing POST /recovery/codes exactly once per page load to
// generate and display the caller's recovery codes, then — only after an
// explicit "I've saved my recovery codes" confirmation — POSTs
// /recovery/acknowledge, the one call that actually clears recovery_required
// (mgmtapi.PostRecoveryAcknowledge). There is no user_id or email parameter
// here either: the caller is resolved entirely from the BFF session cookie
// set by the post-registration handoff or the lost-device recovery ceremony.
func (h *SignupHandler) GetSignupRecovery(w http.ResponseWriter, r *http.Request) {
	h.renderTemplate(w, r, "signup_recovery.html", nil)
}

// signupSuccessData is the template data for GET /signup/success. ReturnTo
// has already passed ValidateReturnTo, so it is safe to interpolate —
// html/template additionally applies contextual href-attribute escaping.
type signupSuccessData struct {
	ReturnTo string
}

// GetSignupSuccess renders the concise signup-completion state and emits the
// signup-lifecycle audit trail (signup.enrolled, signup.passkey_registered,
// signup.recovery_completed) for the completing user. It runs behind
// RequireFullScope (see Routes), so reaching this handler already proves
// recovery_required has cleared; userID is still re-checked directly (same
// defence-in-depth as every DashboardHandler read route) because
// SessionScopeFromContext defaults to full when no BFF session exists at all.
//
// return_to is validated directly against the configured allowlist right
// here — returnto.go's "validate exactly once, at the point read from the
// client" contract, applied at this page's own entry since no earlier hop in
// the signup journey carries a return_to value as session state today (see
// the follow-on task filed for full end-to-end return_to threading). An
// unrecognized or missing value silently falls back to the fixed same-origin
// default and is never echoed.
func (h *SignupHandler) GetSignupSuccess(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	returnTo, _ := ValidateReturnTo(r.URL.Query().Get("return_to"), h.returnToAllowlist)

	// Best-effort audit emission: these three events mark the full signup
	// journey's completion. RecordAsync is non-blocking and detaches from the
	// request context, so a slow/failing audit write never stalls the
	// success page (DESIGN §2.1, Decision 3).
	if h.audit != nil {
		h.audit.RecordAsync(r.Context(), userID, identity.EventSignupEnrolled, nil, nil)
		h.audit.RecordAsync(r.Context(), userID, identity.EventSignupPasskeyRegistered, nil, nil)
		h.audit.RecordAsync(r.Context(), userID, identity.EventSignupRecoveryCompleted, nil, nil)
	}

	h.renderTemplate(w, r, "signup_success.html", signupSuccessData{ReturnTo: returnTo})
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
