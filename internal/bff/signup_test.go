package bff

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/web"
)

// fakeSignupAuditRecorder captures RecordAsync calls synchronously (no
// goroutine) so tests can assert on them deterministically.
type fakeSignupAuditRecorder struct {
	mu     sync.Mutex
	events []fakeSignupAuditEvent
}

type fakeSignupAuditEvent struct {
	userID   string
	et       identity.EventType
	clientID *string
	detail   any
}

func (f *fakeSignupAuditRecorder) RecordAsync(_ context.Context, userID string, et identity.EventType, clientID *string, detail any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, fakeSignupAuditEvent{userID: userID, et: et, clientID: clientID, detail: detail})
}

func newTestSignupHandler(t *testing.T) *SignupHandler {
	t.Helper()
	tmpl, err := web.ParseDashboardTemplates()
	if err != nil {
		t.Fatalf("ParseDashboardTemplates: %v", err)
	}
	h, err := NewSignupHandler(tmpl, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewSignupHandler: %v", err)
	}
	return h
}

func newTestSignupHandlerWithAudit(t *testing.T, audit SignupAuditRecorder, returnToAllowlist []string) *SignupHandler {
	t.Helper()
	tmpl, err := web.ParseDashboardTemplates()
	if err != nil {
		t.Fatalf("ParseDashboardTemplates: %v", err)
	}
	h, err := NewSignupHandler(tmpl, nil, audit, returnToAllowlist, nil)
	if err != nil {
		t.Fatalf("NewSignupHandler: %v", err)
	}
	return h
}

func TestNewSignupHandler_RejectsNilTemplate(t *testing.T) {
	if _, err := NewSignupHandler(nil, nil, nil, nil, nil); err == nil {
		t.Fatal("NewSignupHandler(nil template) = nil error, want error")
	}
}

// TestAllowedSignupRegions_OnlyRegionParseAcceptedCodes proves every code the
// picker offers round-trips through region.Parse, and — since region.Parse
// currently accepts exactly EU/US/APAC — that the full candidate list survives
// the filter (nothing accepted by region.Parse is silently dropped either).
func TestAllowedSignupRegions_OnlyRegionParseAcceptedCodes(t *testing.T) {
	got := allowedSignupRegions()
	if len(got) == 0 {
		t.Fatal("allowedSignupRegions() returned no regions")
	}
	for _, opt := range got {
		if _, err := region.Parse(opt.Code); err != nil {
			t.Errorf("allowedSignupRegions() included %q, but region.Parse(%q) = %v", opt.Code, opt.Code, err)
		}
	}
	if len(got) != len(signupRegionCandidates) {
		t.Errorf("allowedSignupRegions() returned %d regions, want all %d candidates accepted (got %+v)",
			len(got), len(signupRegionCandidates), got)
	}
}

// TestAllowedSignupRegions_FiltersUnknownCandidates proves a candidate code
// region.Parse does not accept is silently dropped from the picker rather than
// rendered as an invalid, unusable option.
func TestAllowedSignupRegions_FiltersUnknownCandidates(t *testing.T) {
	original := signupRegionCandidates
	t.Cleanup(func() { signupRegionCandidates = original })

	signupRegionCandidates = []signupRegionOption{
		{Code: "EU", Label: "European Union"},
		{Code: "MARS", Label: "Mars Colony"},
	}

	got := allowedSignupRegions()
	if len(got) != 1 || got[0].Code != "EU" {
		t.Fatalf("allowedSignupRegions() = %+v, want only the region.Parse-accepted EU candidate", got)
	}
}

// TestGetSignup_RendersOnlyAcceptedRegions renders the live page and confirms
// every region.Parse-accepted candidate appears as a selectable option, and no
// value outside that accepted set is ever rendered.
func TestGetSignup_RendersOnlyAcceptedRegions(t *testing.T) {
	h := newTestSignupHandler(t)

	r := httptest.NewRequest(http.MethodGet, "/signup", nil)
	w := httptest.NewRecorder()
	h.GetSignup(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /signup status = %d, want 200", w.Code)
	}
	body := w.Body.String()

	for _, opt := range allowedSignupRegions() {
		want := `value="` + opt.Code + `"`
		if !strings.Contains(body, want) {
			t.Errorf("GET /signup body missing region option %q", want)
		}
	}

	// A region code that region.Parse rejects must never appear as an option.
	if strings.Contains(body, `value="MARS"`) {
		t.Error("GET /signup body rendered a region.Parse-rejected option")
	}
}

// TestGetSignup_NoUserIDParameter proves the signup page never echoes or
// solicits a client-supplied user_id or email — the enrollment session cookie
// set by POST /enroll is the only supported identity seam (docs/DESIGN.md §9).
func TestGetSignup_NoUserIDParameter(t *testing.T) {
	h := newTestSignupHandler(t)

	r := httptest.NewRequest(http.MethodGet, "/signup?user_id=attacker-supplied", nil)
	w := httptest.NewRecorder()
	h.GetSignup(w, r)

	body := w.Body.String()
	if strings.Contains(body, "user_id") || strings.Contains(body, "attacker-supplied") {
		t.Error("GET /signup response references a client-supplied user_id")
	}
}

func TestGetSignupPasskey_RendersCeremonyPage(t *testing.T) {
	h := newTestSignupHandler(t)

	r := httptest.NewRequest(http.MethodGet, "/signup/passkey", nil)
	w := httptest.NewRecorder()
	h.GetSignupPasskey(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /signup/passkey status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(body, `/webauthn/register/begin`) {
		t.Error("GET /signup/passkey body does not drive /webauthn/register/begin")
	}
	if !strings.Contains(body, `/webauthn/register/finish`) {
		t.Error("GET /signup/passkey body does not drive /webauthn/register/finish")
	}
	if strings.Contains(body, "user_id") {
		t.Error("GET /signup/passkey response references a client-supplied user_id")
	}
}

// TestSignupHandler_Routes proves both routes are wired and answer GET only.
func TestSignupHandler_Routes(t *testing.T) {
	h := newTestSignupHandler(t)
	mux := http.NewServeMux()
	h.Routes(mux)

	for _, path := range []string{"/signup", "/signup/passkey", "/signup/recovery"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", path, w.Code)
		}
	}
}

func TestGetSignupRecovery_RendersRecoveryStep(t *testing.T) {
	h := newTestSignupHandler(t)

	r := httptest.NewRequest(http.MethodGet, "/signup/recovery", nil)
	w := httptest.NewRecorder()
	h.GetSignupRecovery(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /signup/recovery status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(body, `/recovery/codes`) {
		t.Error("GET /signup/recovery body does not drive /recovery/codes")
	}
	if !strings.Contains(body, `/recovery/acknowledge`) {
		t.Error("GET /signup/recovery body does not drive /recovery/acknowledge")
	}
	if strings.Contains(body, "user_id") {
		t.Error("GET /signup/recovery response references a client-supplied user_id")
	}
}

// TestSignupHandler_RecoveryRouteAllowsEnrollmentOnlyScope proves GET
// /signup/recovery is reachable under an enrollment-only session scope (the
// scope the post-registration handoff and lost-device recovery ceremony both
// establish) — it must not 403 the way bff.RequireFullScope routes do.
func TestSignupHandler_RecoveryRouteAllowsEnrollmentOnlyScope(t *testing.T) {
	h := newTestSignupHandler(t)
	mux := http.NewServeMux()
	h.Routes(mux)

	ctx := ContextWithSessionScope(context.Background(), SessionScopeEnrollmentOnly)
	r := httptest.NewRequest(http.MethodGet, "/signup/recovery", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /signup/recovery (enrollment-only scope) status = %d, want 200", w.Code)
	}
}

// fullScopeSignupRequest builds a GET request carrying the context a real
// full-scope BFF session (post-recovery) would inject — ContextWithUserID +
// ContextWithSessionScope(SessionScopeFull) — exactly as bff.Middleware does.
func fullScopeSignupRequest(target, userID string) *http.Request {
	ctx := ContextWithUserID(context.Background(), userID)
	ctx = ContextWithSessionScope(ctx, SessionScopeFull)
	return httptest.NewRequest(http.MethodGet, target, nil).WithContext(ctx)
}

// TestSignupHandler_SuccessRoute_RequiresFullScope proves GET /signup/success
// is unreachable without a full-scope session, mirroring
// TestRequireFullScope_DeniesEnrollmentOnlyScope — a user who has not yet
// completed recovery setup gets a 403, never the success page.
func TestSignupHandler_SuccessRoute_RequiresFullScope(t *testing.T) {
	h := newTestSignupHandler(t)
	mux := http.NewServeMux()
	h.Routes(mux)

	ctx := ContextWithUserID(context.Background(), "user-1")
	ctx = ContextWithSessionScope(ctx, SessionScopeEnrollmentOnly)
	r := httptest.NewRequest(http.MethodGet, "/signup/success", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("GET /signup/success (enrollment-only scope) status = %d, want 403", w.Code)
	}
}

// TestSignupHandler_SuccessRoute_AllowsFullScope proves the counterpart: a
// full-scope session reaches the page.
func TestSignupHandler_SuccessRoute_AllowsFullScope(t *testing.T) {
	h := newTestSignupHandler(t)
	mux := http.NewServeMux()
	h.Routes(mux)

	r := fullScopeSignupRequest("/signup/success", "user-1")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /signup/success (full scope) status = %d, want 200", w.Code)
	}
}

// TestGetSignupSuccess_NoUserIDUnauthorized proves the handler itself
// defends against a request with no authenticated identity even though
// SessionScopeFromContext defaults to full when no scope is set at all
// (e.g. no BFF session cookie was ever presented) — same defence-in-depth
// every DashboardHandler read route applies.
func TestGetSignupSuccess_NoUserIDUnauthorized(t *testing.T) {
	h := newTestSignupHandler(t)

	r := httptest.NewRequest(http.MethodGet, "/signup/success", nil)
	w := httptest.NewRecorder()
	h.GetSignupSuccess(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("GetSignupSuccess with no user ID status = %d, want 401", w.Code)
	}
}

// TestGetSignupSuccess_EmitsAuditEvents proves all three signup-lifecycle
// events are recorded for the completing user's own audit trail, with no RP
// (clientID) context and no PII beyond the userID every other audit call
// site already carries.
func TestGetSignupSuccess_EmitsAuditEvents(t *testing.T) {
	audit := &fakeSignupAuditRecorder{}
	h := newTestSignupHandlerWithAudit(t, audit, nil)

	r := fullScopeSignupRequest("/signup/success", "user-1")
	w := httptest.NewRecorder()
	h.GetSignupSuccess(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GetSignupSuccess status = %d, want 200", w.Code)
	}

	wantEvents := []identity.EventType{
		identity.EventSignupEnrolled,
		identity.EventSignupPasskeyRegistered,
		identity.EventSignupRecoveryCompleted,
	}
	if len(audit.events) != len(wantEvents) {
		t.Fatalf("recorded %d audit events, want %d: %+v", len(audit.events), len(wantEvents), audit.events)
	}
	for i, want := range wantEvents {
		got := audit.events[i]
		if got.et != want {
			t.Errorf("event[%d].et = %q, want %q", i, got.et, want)
		}
		if got.userID != "user-1" {
			t.Errorf("event[%d].userID = %q, want %q", i, got.userID, "user-1")
		}
		if got.clientID != nil {
			t.Errorf("event[%d].clientID = %v, want nil (no RP context at signup)", i, *got.clientID)
		}
		if got.detail != nil {
			t.Errorf("event[%d].detail = %v, want nil (no PII beyond userID)", i, got.detail)
		}
	}
}

// TestGetSignupSuccess_NilAuditRecorderIsGraceful proves a nil audit
// recorder (the default when audit isn't wired) never panics or blocks the
// page render.
func TestGetSignupSuccess_NilAuditRecorderIsGraceful(t *testing.T) {
	h := newTestSignupHandler(t)

	r := fullScopeSignupRequest("/signup/success", "user-1")
	w := httptest.NewRecorder()
	h.GetSignupSuccess(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GetSignupSuccess with nil audit recorder status = %d, want 200", w.Code)
	}
}
