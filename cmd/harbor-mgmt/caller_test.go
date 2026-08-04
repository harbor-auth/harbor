package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/harbor-auth/harbor/internal/bff"
	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/harbor-auth/harbor/internal/mgmtapi"
	bfftest "github.com/harbor-auth/harbor/internal/testsupport/bff"
	mgmtapitest "github.com/harbor-auth/harbor/internal/testsupport/mgmtapi"
)

type callerTestEnroller struct{}

func (callerTestEnroller) Enroll(context.Context, string) (identity.EnrollResult, error) {
	return identity.EnrollResult{}, nil
}

type callerTestRegistrationStore struct{}

func (callerTestRegistrationStore) Create(context.Context, clients.NewRegisteredClient) (clients.RegisteredClient, error) {
	return clients.RegisteredClient{}, nil
}

func newCallerTestServer(t *testing.T) *mgmtapi.Server {
	t.Helper()
	srv, err := mgmtapi.New(callerTestEnroller{}, mgmtapitest.NewInMemoryEnrollmentSessionStore(), callerTestRegistrationStore{}, "https://mgmt.example.com", nil)
	if err != nil {
		t.Fatalf("mgmtapi.New: %v", err)
	}
	return srv
}

// TestBffCallerAdapter_SpoofedHeader_NoSession is a cmd-level integration test
// that wires the real bff.Middleware and bffCallerAdapter together and confirms
// that a request carrying a spoofed X-Harbor-User-ID header but no BFF session
// cookie is rejected with 401.
//
// This exercises the full auth seam used in production (cmd/harbor-mgmt):
//
//  1. bff.Middleware reads the __Host-harbor-bff cookie; no cookie → no user
//     is placed in the context.
//  2. bffCallerAdapter.CallerID delegates to bff.UserIDFromContext; the
//     context carries no user → returns "".
//  3. mgmtapi.(*Server).callerID writes 401 and returns ok=false.
//
// The spoofed X-Harbor-User-ID header is present throughout but is never
// consulted by any layer — confirming the header-spoofing vulnerability
// (audit finding C1) is closed at the cmd wiring level.
func TestBffCallerAdapter_SpoofedHeader_NoSession(t *testing.T) {
	store := bfftest.NewInMemoryBFFSessionStore()

	// Wire the same way cmd/harbor-mgmt/main.go does (lines ~288, ~377).
	srv := newCallerTestServer(t).WithCallerSource(bffCallerAdapter{})
	mux := http.NewServeMux()
	srv.Routes(mux)
	handler := bff.Middleware(store)(mux)

	// Send a request with a spoofed identity header but no session cookie.
	req := httptest.NewRequest(http.MethodGet, "/consent-grants", nil)
	req.Header.Set("X-Harbor-User-ID", "victim-user")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY: status = %d, want 401; "+
			"spoofed X-Harbor-User-ID header must not grant access when no BFF session cookie is present",
			rec.Code)
	}
}

// TestBffCallerAdapter_SpoofedHeader_WithSession verifies that even when a
// valid BFF session exists for user-A, a request that also carries
// X-Harbor-User-ID: user-B is scoped to user-A (the session user).
//
// With no consent store wired the response is 503 (service unavailable), NOT
// 401. Any status other than 401 proves the session identity was resolved: a
// 401 would mean no identity was found (i.e., the spoofed header was silently
// adopted instead of the session).
func TestBffCallerAdapter_SpoofedHeader_WithSession(t *testing.T) {
	store := bfftest.NewInMemoryBFFSessionStore()

	const sessionUser = "user-A"
	const spoofedUser = "user-B"

	// Seed a real BFF session for user-A. ExpiresAt must be in the future so
	// the in-memory store's TTL check passes on SetUser.
	ctx := context.Background()
	if err := store.Create(ctx, bff.BFFSessionRecord{
		RequestID: "sess-001",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	if err := store.SetUser(ctx, "sess-001", sessionUser); err != nil {
		t.Fatalf("store.SetUser: %v", err)
	}

	srv := newCallerTestServer(t).WithCallerSource(bffCallerAdapter{})
	mux := http.NewServeMux()
	srv.Routes(mux)
	handler := bff.Middleware(store)(mux)

	// Request carries a spoofed user-B header AND the real user-A session cookie.
	req := httptest.NewRequest(http.MethodGet, "/consent-grants", nil)
	req.Header.Set("X-Harbor-User-ID", spoofedUser)
	req.AddCookie(&http.Cookie{Name: bff.CookieName, Value: "sess-001"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// 503 = caller was resolved (user-A from session) but consent store is nil.
	// 401 = no caller resolved, which would indicate the session was not used
	//       and the spoofed header path is live — a security regression.
	if rec.Code == http.StatusUnauthorized {
		t.Errorf("SECURITY: status = 401; valid session for %q must not be overridden by spoofed header %q — session identity must win",
			sessionUser, spoofedUser)
	}
}

func TestBffCallerAdapter_EnrollmentOnlySessionCannotCallManagementAPI(t *testing.T) {
	ctx := bff.ContextWithUserID(context.Background(), "recovering-user")
	ctx = bff.ContextWithSessionScope(ctx, bff.SessionScopeEnrollmentOnly)
	if got := (bffCallerAdapter{}).CallerID(ctx); got != "" {
		t.Fatalf("CallerID(enrollment-only session) = %q, want empty", got)
	}
}

func TestRecoverySessionIssuerBindsBFFAndEnrollmentRecords(t *testing.T) {
	ctx := context.Background()
	bffSessions := bfftest.NewInMemoryBFFSessionStore()
	enrollmentSessions := mgmtapitest.NewInMemoryEnrollmentSessionStore()
	issuer := &recoverySessionIssuer{
		bffSessions:        bffSessions,
		enrollmentSessions: enrollmentSessions,
	}

	const userID = "550e8400-e29b-41d4-a716-446655440000"
	const returnTo = "/dashboard/after-signup"
	token, err := issuer.IssueEnrollmentSession(ctx, userID, returnTo)
	if err != nil {
		t.Fatalf("IssueEnrollmentSession: %v", err)
	}
	record, err := bffSessions.Get(ctx, token)
	if err != nil {
		t.Fatalf("BFF session Get: %v", err)
	}
	if record.UserID != userID || !record.RecoveryRequired || record.SessionScope != bff.SessionScopeEnrollmentOnly {
		t.Fatalf("BFF session = %+v, want enrollment-only recovery session for %q", record, userID)
	}
	if record.ReturnTo != returnTo {
		t.Fatalf("BFF session ReturnTo = %q, want %q", record.ReturnTo, returnTo)
	}
	handle, recovery, gotReturnTo, err := enrollmentSessions.UserHandle(ctx, token)
	if err != nil {
		t.Fatalf("enrollment session UserHandle: %v", err)
	}
	wantHandle := uuid.MustParse(userID)
	if !bytes.Equal(handle, wantHandle[:]) {
		t.Fatalf("user handle = %x, want UUID bytes %x", handle, wantHandle[:])
	}
	if !recovery {
		t.Fatal("enrollment session recovery = false, want true: register/finish must route through svc.FinishRecoveryRegistration")
	}
	if gotReturnTo != returnTo {
		t.Fatalf("enrollment session ReturnTo = %q, want %q", gotReturnTo, returnTo)
	}
}

// TestPostRegistrationHandoffAndRecoveryGating_EndToEnd is the composed
// regression test for Task 3's "Done when" criteria: it wires the SAME
// collaborators main.go wires (bff.Middleware, wirePostRegistrationHandoff,
// mgmtapi.Server with the new recovery-completion pieces) against in-memory
// stores and drives the full journey a browser would:
//
//  1. POST /webauthn/register/finish succeeds (simulated) → the
//     post-registration handoff lands the caller in an enrollment-only BFF
//     session, mirroring PostRecoveryComplete.
//  2. That session is refused by a bff.RequireFullScope route with the
//     existing generic 403 — recovery setup is not done yet.
//  3. POST /recovery/acknowledge (available under enrollment-only scope via
//     bffEnrollmentCallerAdapter) succeeds.
//  4. The SAME cookie now passes the bff.RequireFullScope route — no fresh
//     sign-in required.
func TestPostRegistrationHandoffAndRecoveryGating_EndToEnd(t *testing.T) {
	ctx := context.Background()
	const userID = "550e8400-e29b-41d4-a716-446655440000"
	handle := uuid.MustParse(userID)

	bffSessions := bfftest.NewInMemoryBFFSessionStore()
	enrollmentSessions := mgmtapitest.NewInMemoryEnrollmentSessionStore()
	if err := enrollmentSessions.Save(ctx, "enroll-key", handle[:], false, ""); err != nil {
		t.Fatalf("seed enrollment session: %v", err)
	}
	issuer := &recoverySessionIssuer{bffSessions: bffSessions, enrollmentSessions: enrollmentSessions}
	refresher := bffSessionScopeRefresher{bffSessions: bffSessions}

	fakeFinish := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"registered"}`))
	})
	finishRoute := wirePostRegistrationHandoff(fakeFinish, enrollmentSessions, issuer, refresher, discardLogger())

	mgmtServer := newCallerTestServer(t)
	mgmtServer.
		WithCallerSource(bffCallerAdapter{}).
		WithRecoveryRequirementClearer(recoveryRequirementClearer{store: &fakeRecoveryCompleteStore{}}).
		WithRecoverySessionRefresher(bffSessionScopeRefresher{bffSessions: bffSessions}).
		WithEnrollmentCallerSource(bffEnrollmentCallerAdapter{})

	mux := http.NewServeMux()
	mux.Handle("POST /webauthn/register/finish", finishRoute)
	mgmtServer.Routes(mux)
	mux.Handle("GET /dashboard-ish", bff.RequireFullScope(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	handler := bff.Middleware(bffSessions)(mux)

	// Step 1: first successful passkey registration.
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", nil)
	req.AddCookie(&http.Cookie{Name: mgmtapi.EnrollmentSessionCookieName, Value: "enroll-key"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("register/finish status = %d, want 200", rec.Code)
	}
	var bffCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == bff.CookieName {
			bffCookie = c
		}
	}
	if bffCookie == nil {
		t.Fatalf("register/finish response set no %s cookie; got %+v", bff.CookieName, rec.Result().Cookies())
	}

	// Step 2: the enrollment-only session is refused by RequireFullScope.
	req = httptest.NewRequest(http.MethodGet, "/dashboard-ish", nil)
	req.AddCookie(bffCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("RequireFullScope before recovery setup: status = %d, want 403", rec.Code)
	}

	// Step 3: complete the mandatory recovery step.
	req = httptest.NewRequest(http.MethodPost, "/recovery/acknowledge", strings.NewReader("{}"))
	req.AddCookie(bffCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /recovery/acknowledge status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Step 4: the SAME cookie now passes RequireFullScope.
	req = httptest.NewRequest(http.MethodGet, "/dashboard-ish", nil)
	req.AddCookie(bffCookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("RequireFullScope after recovery setup: status = %d, want 200", rec.Code)
	}
}

// TestPostRegistrationHandoff_LostDeviceRecovery_DoesNotReArmRecoveryRequired
// is the regression test for the interaction between Task 3's post-
// registration handoff and Task 12's fix routing a lost-device recovery
// ceremony's register/finish through svc.FinishRecoveryRegistration.
//
// wirePostRegistrationHandoff fires on EVERY successful register/finish, first
// signup and lost-device recovery alike. Before this fix it always called
// ScopedSessionIssuer.IssueEnrollmentSession, which unconditionally mints a
// BRAND NEW SessionScopeEnrollmentOnly/RecoveryRequired=true BFF session —
// even when the request that just completed IS the lost-device recovery
// ceremony that cleared users.recovery_required moments earlier. That defeats
// the DB clear for the session the browser is actually holding: the same
// request that proved recovery re-arms the enrollment-only gate, sending the
// user straight back into /signup/recovery.
//
// This test seeds the SAME enrollment-only/recovery-required BFF+enrollment
// session pair POST /recovery/complete produces (recovery=true), drives a
// simulated successful register/finish through the real wirePostRegistrationHandoff,
// and asserts the ORIGINAL cookie — not a freshly minted one — passes
// bff.RequireFullScope immediately afterward, matching REQ-003's spec
// scenario ("a later RequireFullScope route succeeds for that user") and
// user-account-recovery's REQ-003 ("deny every other surface... until
// recovery_required is cleared" — implying access resumes once it is).
func TestPostRegistrationHandoff_LostDeviceRecovery_DoesNotReArmRecoveryRequired(t *testing.T) {
	ctx := context.Background()
	const userID = "550e8400-e29b-41d4-a716-446655440000"
	handle := uuid.MustParse(userID)
	const recoveryToken = "recovery-scoped-token"

	bffSessions := bfftest.NewInMemoryBFFSessionStore()
	enrollmentSessions := mgmtapitest.NewInMemoryEnrollmentSessionStore()

	// Seed exactly what a prior, successful POST /recovery/complete leaves
	// behind: an enrollment-only/recovery-required BFF session AND an
	// enrollment-session handoff record with recovery=true, both keyed by the
	// same opaque token (recoverySessionIssuer.IssueEnrollmentSession's
	// contract).
	if err := bffSessions.Create(ctx, bff.BFFSessionRecord{
		RequestID:        recoveryToken,
		UserID:           userID,
		SessionScope:     bff.SessionScopeEnrollmentOnly,
		RecoveryRequired: true,
		ExpiresAt:        time.Now().Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("seed recovery-scoped BFF session: %v", err)
	}
	if err := enrollmentSessions.Save(ctx, recoveryToken, handle[:], true, ""); err != nil {
		t.Fatalf("seed recovery enrollment handoff: %v", err)
	}

	// The wrapped ceremony handler simulates a successful register/finish that
	// routed to svc.FinishRecoveryRegistration (Task 12): it reports 200 and,
	// in production, users.recovery_required is now false in the DB.
	fakeFinish := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"registered"}`))
	})
	issuer := &recordingScopedSessionIssuer{token: "should-not-be-issued"}
	refresher := bffSessionScopeRefresher{bffSessions: bffSessions}
	finishRoute := wirePostRegistrationHandoff(fakeFinish, enrollmentSessions, issuer, refresher, discardLogger())

	mux := http.NewServeMux()
	mux.Handle("POST /webauthn/register/finish", finishRoute)
	mux.Handle("GET /dashboard-ish", bff.RequireFullScope(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	handler := bff.Middleware(bffSessions)(mux)

	// Drive the recovery ceremony's register/finish carrying the recovery-
	// scoped cookie pair a browser would present at this point.
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", nil)
	req.AddCookie(&http.Cookie{Name: mgmtapi.EnrollmentSessionCookieName, Value: recoveryToken})
	req.AddCookie(&http.Cookie{Name: bff.CookieName, Value: recoveryToken})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("register/finish status = %d, want 200", rec.Code)
	}

	if issuer.called {
		t.Error("a lost-device recovery register/finish must not mint a brand new enrollment-only session — it must refresh the existing one in place")
	}
	for _, c := range rec.Result().Cookies() {
		if (c.Name == mgmtapi.RecoveryScopedSessionCookieName || c.Name == mgmtapi.EnrollmentSessionCookieName) && c.Value != recoveryToken {
			t.Errorf("register/finish set %s=%q, want no cookie overwrite (still %q, the existing recovery session's own token)", c.Name, c.Value, recoveryToken)
		}
	}

	// The ORIGINAL cookie (no fresh sign-in, no newly minted token) must now
	// pass RequireFullScope: the recovery ceremony that just cleared
	// recovery_required must not have re-armed it for this same session.
	req = httptest.NewRequest(http.MethodGet, "/dashboard-ish", nil)
	req.AddCookie(&http.Cookie{Name: bff.CookieName, Value: recoveryToken})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("RequireFullScope after lost-device recovery register/finish: status = %d, want 200 (recovery_required must not be re-armed)", rec.Code)
	}
}

func TestRecoveryRequirementClearer_AdaptsSetRecoveryComplete(t *testing.T) {
	store := &fakeRecoveryCompleteStore{}
	c := recoveryRequirementClearer{store: store}

	const userID = "550e8400-e29b-41d4-a716-446655440000"
	if err := c.ClearRecoveryRequired(context.Background(), userID); err != nil {
		t.Fatalf("ClearRecoveryRequired: %v", err)
	}
	if string(store.gotUserID) != userID {
		t.Fatalf("SetRecoveryComplete called with %q, want the canonical UUID text %q unchanged", store.gotUserID, userID)
	}
}

type fakeRecoveryCompleteStore struct {
	gotUserID []byte
	err       error
}

func (f *fakeRecoveryCompleteStore) SetRecoveryComplete(_ context.Context, userID []byte) error {
	f.gotUserID = userID
	return f.err
}

func TestBFFSessionScopeRefresher_UpdatesRecoveryStatus(t *testing.T) {
	store := bfftest.NewInMemoryBFFSessionStore()
	ctx := context.Background()
	if err := store.Create(ctx, bff.BFFSessionRecord{
		RequestID:        "sess-1",
		UserID:           "user-1",
		SessionScope:     bff.SessionScopeEnrollmentOnly,
		RecoveryRequired: true,
		ExpiresAt:        time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}

	r := bffSessionScopeRefresher{bffSessions: store}
	if err := r.RefreshSessionScope(ctx, "sess-1", "user-1", false); err != nil {
		t.Fatalf("RefreshSessionScope: %v", err)
	}

	record, err := store.Get(ctx, "sess-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if record.RecoveryRequired || record.SessionScope != bff.SessionScopeFull {
		t.Fatalf("session = %+v, want RecoveryRequired=false SessionScope=full", record)
	}
}

func TestBFFSessionScopeRefresher_MissingSessionIDFailsClosed(t *testing.T) {
	r := bffSessionScopeRefresher{bffSessions: bfftest.NewInMemoryBFFSessionStore()}
	if err := r.RefreshSessionScope(context.Background(), "", "user-1", false); err == nil {
		t.Fatal("RefreshSessionScope(empty sessionID) = nil error, want error")
	}
}

// TestBffEnrollmentCallerAdapter_ResolvesEnrollmentOnlySession proves the
// enrollment-scoped adapter — unlike bffCallerAdapter — resolves the caller
// even under SessionScopeEnrollmentOnly, since it is wired ONLY to the two
// recovery-setup endpoints that are explicitly safe under that scope.
func TestBffEnrollmentCallerAdapter_ResolvesEnrollmentOnlySession(t *testing.T) {
	ctx := bff.ContextWithUserID(context.Background(), "recovering-user")
	ctx = bff.ContextWithSessionScope(ctx, bff.SessionScopeEnrollmentOnly)
	if got := (bffEnrollmentCallerAdapter{}).CallerID(ctx); got != "recovering-user" {
		t.Fatalf("CallerID(enrollment-only session) = %q, want %q", got, "recovering-user")
	}
}

// TestWirePostRegistrationHandoff_IssuesSessionOnlyOn200 proves the handoff
// wrapper fires ScopedSessionIssuer.IssueEnrollmentSession exactly when the
// wrapped ceremony handler reports success, resolving the user id from the
// SAME enrollment-session cookie the ceremony itself reads.
func TestWirePostRegistrationHandoff_IssuesSessionOnlyOn200(t *testing.T) {
	const userID = "550e8400-e29b-41d4-a716-446655440000"
	handle := uuid.MustParse(userID)

	newHandoff := func(status int) (http.Handler, *mgmtapitest.InMemoryEnrollmentSessionStore, *recordingScopedSessionIssuer) {
		sessions := mgmtapitest.NewInMemoryEnrollmentSessionStore()
		if err := sessions.Save(context.Background(), "enroll-key", handle[:], false, "/dashboard/after-signup"); err != nil {
			t.Fatalf("seed enrollment session: %v", err)
		}
		issuer := &recordingScopedSessionIssuer{token: "issued-token"}
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
		h := wirePostRegistrationHandoff(next, sessions, issuer, nil, discardLogger())
		return h, sessions, issuer
	}

	t.Run("200 issues the enrollment session and cookies", func(t *testing.T) {
		h, _, issuer := newHandoff(http.StatusOK)
		req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", nil)
		req.AddCookie(&http.Cookie{Name: mgmtapi.EnrollmentSessionCookieName, Value: "enroll-key"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if issuer.gotUserID != userID {
			t.Fatalf("issuer got userID = %q, want %q", issuer.gotUserID, userID)
		}
		if issuer.gotReturnTo != "/dashboard/after-signup" {
			t.Fatalf("issuer got returnTo = %q, want %q — the enrollment session's return_to must be copied through the handoff",
				issuer.gotReturnTo, "/dashboard/after-signup")
		}
		var sawScoped, sawEnrollment bool
		for _, c := range rec.Result().Cookies() {
			switch c.Name {
			case mgmtapi.RecoveryScopedSessionCookieName:
				sawScoped = c.Value == "issued-token"
			case mgmtapi.EnrollmentSessionCookieName:
				sawEnrollment = c.Value == "issued-token"
			}
		}
		if !sawScoped || !sawEnrollment {
			t.Fatalf("cookies = %+v, want both %s and %s set to the issued token",
				rec.Result().Cookies(), mgmtapi.RecoveryScopedSessionCookieName, mgmtapi.EnrollmentSessionCookieName)
		}
	})

	t.Run("non-200 never issues a session", func(t *testing.T) {
		h, _, issuer := newHandoff(http.StatusBadRequest)
		req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", nil)
		req.AddCookie(&http.Cookie{Name: mgmtapi.EnrollmentSessionCookieName, Value: "enroll-key"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if issuer.called {
			t.Error("issuer must not be called for a non-200 ceremony response")
		}
	})

	t.Run("missing enrollment cookie never issues a session", func(t *testing.T) {
		h, _, issuer := newHandoff(http.StatusOK)
		req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if issuer.called {
			t.Error("issuer must not be called without an enrollment-session cookie")
		}
	})

	t.Run("issuer failure still returns the ceremony's own success", func(t *testing.T) {
		sessions := mgmtapitest.NewInMemoryEnrollmentSessionStore()
		if err := sessions.Save(context.Background(), "enroll-key", handle[:], false, ""); err != nil {
			t.Fatalf("seed enrollment session: %v", err)
		}
		issuer := &recordingScopedSessionIssuer{err: errors.New("redis down")}
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"registered"}`))
		})
		h := wirePostRegistrationHandoff(next, sessions, issuer, nil, discardLogger())

		req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", nil)
		req.AddCookie(&http.Cookie{Name: mgmtapi.EnrollmentSessionCookieName, Value: "enroll-key"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 even though the handoff itself failed", rec.Code)
		}
		if rec.Body.String() != `{"status":"registered"}` {
			t.Fatalf("body = %q, want the ceremony handler's own untouched body", rec.Body.String())
		}
	})
}

// recordingScopedSessionIssuer is a test-only mgmtapi.ScopedSessionIssuer that
// records the userID and returnTo it was called with.
type recordingScopedSessionIssuer struct {
	token       string
	err         error
	called      bool
	gotUserID   string
	gotReturnTo string
}

func (r *recordingScopedSessionIssuer) IssueEnrollmentSession(_ context.Context, userID, returnTo string) (string, error) {
	r.called = true
	r.gotUserID = userID
	r.gotReturnTo = returnTo
	if r.err != nil {
		return "", r.err
	}
	return r.token, nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestProductionRoutesExposeOneEnrollmentFrontDoor guards the composition
// root's route ownership. mgmtapi owns POST /enroll; cmd/harbor-mgmt must not
// also expose the legacy POST /users/enroll handler, which bypasses the
// distributed enrollment-session handoff used by the WebAuthn handler.
func TestProductionRoutesExposeOneEnrollmentFrontDoor(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if strings.Contains(string(source), `HandleFunc("POST /users/enroll"`) {
		t.Fatal("legacy POST /users/enroll route bypasses the canonical distributed enrollment flow")
	}
}
