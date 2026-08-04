package bff

// Tests for threading return_to as real server-side session state through the
// signup journey (design.md Decision 5 / REQ-004): validated once at GET
// /signup, carried via a short-lived cookie into the new enrollment session
// (see mgmtapi.SignupReturnToCookieName), and honored at GET /signup/success
// either directly on that page's own URL or via the BFF session the
// post-registration handoff / lost-device recovery ceremony issued. Split out
// of signup_test.go (§1.10: one concern per file) once the file grew past the
// 500-line test budget.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/mgmtapi"
	"github.com/harbor-auth/harbor/web"
)

func newTestSignupHandlerWithSessions(t *testing.T, sessions BFFSessionStore) *SignupHandler {
	t.Helper()
	tmpl, err := web.ParseDashboardTemplates()
	if err != nil {
		t.Fatalf("ParseDashboardTemplates: %v", err)
	}
	h, err := NewSignupHandler(tmpl, sessions, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewSignupHandler: %v", err)
	}
	return h
}

// TestGetSignup_SetsValidatedReturnToCookie proves GET /signup validates
// return_to exactly once and stashes the ACCEPTED value (never the raw one)
// in the SignupReturnToCookieName cookie, so POST /enroll can fold it into
// the new enrollment session as real server-side state (design.md Decision 5
// / REQ-004).
func TestGetSignup_SetsValidatedReturnToCookie(t *testing.T) {
	h := newTestSignupHandlerWithAudit(t, nil, []string{"marketing.example"})

	r := httptest.NewRequest(http.MethodGet, "/signup?return_to=https%3A%2F%2Fmarketing.example%2Fwelcome", nil)
	w := httptest.NewRecorder()
	h.GetSignup(w, r)

	var got *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == mgmtapi.SignupReturnToCookieName {
			got = c
		}
	}
	if got == nil {
		t.Fatalf("GET /signup set no %s cookie; got %+v", mgmtapi.SignupReturnToCookieName, w.Result().Cookies())
	}
	if got.Value != "https://marketing.example/welcome" {
		t.Errorf("%s cookie = %q, want the allowlisted return_to", mgmtapi.SignupReturnToCookieName, got.Value)
	}
	if !got.HttpOnly || !got.Secure {
		t.Errorf("%s cookie must be HttpOnly and Secure, got HttpOnly=%v Secure=%v", mgmtapi.SignupReturnToCookieName, got.HttpOnly, got.Secure)
	}
}

// TestGetSignup_UnrecognizedReturnToNeverReachesCookie proves an unrecognized
// host is never stashed verbatim in the cookie — it falls back to the fixed
// same-origin default, same as every other ValidateReturnTo call site.
func TestGetSignup_UnrecognizedReturnToNeverReachesCookie(t *testing.T) {
	h := newTestSignupHandlerWithAudit(t, nil, []string{"marketing.example"})

	r := httptest.NewRequest(http.MethodGet, "/signup?return_to=https%3A%2F%2Fevil.example%2Fphish", nil)
	w := httptest.NewRecorder()
	h.GetSignup(w, r)

	var got *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == mgmtapi.SignupReturnToCookieName {
			got = c
		}
	}
	if got == nil {
		t.Fatalf("GET /signup set no %s cookie", mgmtapi.SignupReturnToCookieName)
	}
	if got.Value != "/" {
		t.Errorf("%s cookie = %q, want the fixed same-origin default", mgmtapi.SignupReturnToCookieName, got.Value)
	}
}

// TestGetSignupSuccess_ReturnToAllowlisted proves an absolute return_to on an
// allowlisted host is rendered exactly as given.
func TestGetSignupSuccess_ReturnToAllowlisted(t *testing.T) {
	h := newTestSignupHandlerWithAudit(t, nil, []string{"marketing.example"})

	r := fullScopeSignupRequest("/signup/success?return_to=https%3A%2F%2Fmarketing.example%2Fwelcome", "user-1")
	w := httptest.NewRecorder()
	h.GetSignupSuccess(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GetSignupSuccess status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `href="https://marketing.example/welcome"`) {
		t.Errorf("GetSignupSuccess body = %q, want a link to the allowlisted return_to", body)
	}
}

// TestGetSignupSuccess_UnrecognizedReturnToFallsBackToDefault proves a
// foreign, non-allowlisted host is never rendered — the response falls back
// to the fixed same-origin default and the rejected value is never echoed.
func TestGetSignupSuccess_UnrecognizedReturnToFallsBackToDefault(t *testing.T) {
	h := newTestSignupHandlerWithAudit(t, nil, []string{"marketing.example"})

	r := fullScopeSignupRequest("/signup/success?return_to=https%3A%2F%2Fevil.example%2Fphish", "user-1")
	w := httptest.NewRecorder()
	h.GetSignupSuccess(w, r)

	body := w.Body.String()
	if strings.Contains(body, "evil.example") {
		t.Fatalf("GetSignupSuccess body echoed an unrecognized return_to host: %q", body)
	}
	if !strings.Contains(body, `href="/"`) {
		t.Errorf("GetSignupSuccess body = %q, want a link to the fixed same-origin default", body)
	}
}

// TestGetSignupSuccess_MissingReturnToFallsBackToDefault proves the absence
// of a return_to parameter also falls back to the fixed default.
func TestGetSignupSuccess_MissingReturnToFallsBackToDefault(t *testing.T) {
	h := newTestSignupHandler(t)

	r := fullScopeSignupRequest("/signup/success", "user-1")
	w := httptest.NewRecorder()
	h.GetSignupSuccess(w, r)

	body := w.Body.String()
	if !strings.Contains(body, `href="/"`) {
		t.Errorf("GetSignupSuccess body = %q, want a link to the fixed same-origin default", body)
	}
}

// fullScopeSignupRequestWithSession is fullScopeSignupRequest plus a session
// ID in context (SessionIDFromContext), matching what bff.Middleware injects
// for a real BFF session — needed to exercise GetSignupSuccess's fallback to
// the return_to carried on that session record.
func fullScopeSignupRequestWithSession(target, userID, sessionID string) *http.Request {
	ctx := ContextWithUserID(context.Background(), userID)
	ctx = ContextWithSessionScope(ctx, SessionScopeFull)
	ctx = context.WithValue(ctx, sessionIDKey{}, sessionID)
	return httptest.NewRequest(http.MethodGet, target, nil).WithContext(ctx)
}

// TestGetSignupSuccess_FallsBackToSessionCarriedReturnTo proves the whole
// point of this task: a return_to captured once at GET /signup and carried as
// server-side session state (design.md Decision 5 / REQ-004) — never supplied
// on /signup/success's own URL — is still honored here, because it was
// threaded through IssueEnrollmentSession onto the caller's BFF session.
func TestGetSignupSuccess_FallsBackToSessionCarriedReturnTo(t *testing.T) {
	sessions := NewInMemoryBFFSessionStore()
	if err := sessions.Create(context.Background(), BFFSessionRecord{
		RequestID: "sess-1",
		UserID:    "user-1",
		ReturnTo:  "/dashboard/after-signup",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed BFF session: %v", err)
	}
	h := newTestSignupHandlerWithSessions(t, sessions)

	r := fullScopeSignupRequestWithSession("/signup/success", "user-1", "sess-1")
	w := httptest.NewRecorder()
	h.GetSignupSuccess(w, r)

	body := w.Body.String()
	if !strings.Contains(body, `href="/dashboard/after-signup"`) {
		t.Errorf("GetSignupSuccess body = %q, want a link to the session-carried return_to", body)
	}
}

// TestGetSignupSuccess_QueryReturnToTakesPriorityOverSession proves an
// explicit return_to directly on /signup/success's own URL still wins over a
// session-carried value — preserving the page's original single-hop contract
// (e.g. a link shared directly to /signup/success?return_to=...) rather than
// silently ignoring it now that a session-carried fallback exists.
func TestGetSignupSuccess_QueryReturnToTakesPriorityOverSession(t *testing.T) {
	sessions := NewInMemoryBFFSessionStore()
	if err := sessions.Create(context.Background(), BFFSessionRecord{
		RequestID: "sess-1",
		UserID:    "user-1",
		ReturnTo:  "/from-session",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed BFF session: %v", err)
	}
	tmpl, err := web.ParseDashboardTemplates()
	if err != nil {
		t.Fatalf("ParseDashboardTemplates: %v", err)
	}
	h, err := NewSignupHandler(tmpl, sessions, nil, []string{"marketing.example"}, nil)
	if err != nil {
		t.Fatalf("NewSignupHandler: %v", err)
	}

	r := fullScopeSignupRequestWithSession(
		"/signup/success?return_to=https%3A%2F%2Fmarketing.example%2Fwelcome", "user-1", "sess-1")
	w := httptest.NewRecorder()
	h.GetSignupSuccess(w, r)

	body := w.Body.String()
	if !strings.Contains(body, `href="https://marketing.example/welcome"`) {
		t.Errorf("GetSignupSuccess body = %q, want the query return_to to win over the session-carried one", body)
	}
	if strings.Contains(body, "/from-session") {
		t.Errorf("GetSignupSuccess body = %q, must not fall back to the session value when the query value is accepted", body)
	}
}

// TestGetSignupSuccess_NilSessionsIsGraceful proves a nil sessions store (the
// default when it isn't wired) never panics and simply behaves like before
// this fallback existed.
func TestGetSignupSuccess_NilSessionsIsGraceful(t *testing.T) {
	h := newTestSignupHandler(t)

	r := fullScopeSignupRequestWithSession("/signup/success", "user-1", "sess-1")
	w := httptest.NewRecorder()
	h.GetSignupSuccess(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GetSignupSuccess with nil sessions status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `href="/"`) {
		t.Errorf("GetSignupSuccess body = %q, want a link to the fixed same-origin default", body)
	}
}
