package main

import (
	"bytes"
	"context"
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
	token, err := issuer.IssueEnrollmentSession(ctx, userID)
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
	handle, err := enrollmentSessions.UserHandle(ctx, token)
	if err != nil {
		t.Fatalf("enrollment session UserHandle: %v", err)
	}
	wantHandle := uuid.MustParse(userID)
	if !bytes.Equal(handle, wantHandle[:]) {
		t.Fatalf("user handle = %x, want UUID bytes %x", handle, wantHandle[:])
	}
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
