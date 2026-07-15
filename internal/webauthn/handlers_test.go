package webauthn

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// testEnrollKey is an arbitrary enrollment session key value; the fake store
// ignores the key and returns its configured user handle.
const testEnrollKey = "test-enroll-key"

// fakeEnrollmentSessionStore is an in-memory enrollment session store for tests.
// It resolves every key to userHandle (or returns err, simulating an expired or
// unknown session).
type fakeEnrollmentSessionStore struct {
	userHandle []byte
	err        error
}

func (f *fakeEnrollmentSessionStore) UserHandle(_ context.Context, _ string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.userHandle, nil
}

// enrollReq builds a ceremony request carrying the enrollment session cookie so
// the handler resolves the user handle from the (fake) enrollment store — the
// production path that replaced the insecure user_id query param.
func enrollReq(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.AddCookie(&http.Cookie{Name: enrollmentCookieName, Value: testEnrollKey})
	return req
}

// newCeremonyMux returns a mux whose handler resolves the ceremony user handle
// (via the enrollment cookie) to userHandle. The service is built by
// newTestService, whose store contains the "demo-user" account (no credentials).
func newCeremonyMux(t *testing.T, userHandle []byte) *http.ServeMux {
	t.Helper()
	svc, _ := newTestService(t)
	return muxForService(svc, userHandle)
}

// muxForService wires handler routes for svc with an enrollment store resolving
// to userHandle.
func muxForService(svc *Service, userHandle []byte) *http.ServeMux {
	handler := NewHandler(svc).WithEnrollmentSessions(&fakeEnrollmentSessionStore{userHandle: userHandle})
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	return mux
}

func demoHandle() []byte { return []byte("demo-user") }

// --- registration -----------------------------------------------------------

func TestHandler_BeginRegistration_OK(t *testing.T) {
	mux := newCeremonyMux(t, demoHandle())
	req := enrollReq(http.MethodPost, "/webauthn/register/begin", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	var foundCookie bool
	for _, c := range res.Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			foundCookie = true
			if !c.HttpOnly {
				t.Fatal("session cookie must be HttpOnly")
			}
		}
	}
	if !foundCookie {
		t.Fatal("expected a session cookie to be set")
	}
}

func TestHandler_BeginRegistration_UnknownUser(t *testing.T) {
	mux := newCeremonyMux(t, []byte("nobody"))
	req := enrollReq(http.MethodPost, "/webauthn/register/begin", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Unknown user is deliberately indistinguishable from a bad request (400) to
	// prevent user-handle enumeration (docs/DESIGN.md §6.5).
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

// CRITICAL: with no enrollment session store wired there is NO way to name the
// ceremony's user (the insecure user_id query param has been removed), so every
// endpoint refuses the request with 501 — even when a legacy user_id param is
// supplied (docs/DESIGN.md §9 — IDOR defense).
func TestHandler_NoEnrollmentStore_Returns501(t *testing.T) {
	svc, _ := newTestService(t)
	mux := http.NewServeMux()
	RegisterRoutes(mux, svc) // no enrollment sessions wired

	for _, path := range []string{
		"/webauthn/register/begin",
		"/webauthn/register/finish",
		"/webauthn/login/begin",
		"/webauthn/login/finish",
	} {
		// Include a legacy user_id query param to prove it is ignored.
		req := httptest.NewRequest(http.MethodPost, path+"?user_id=ZGVtby11c2Vy", strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Result().StatusCode != http.StatusNotImplemented {
			t.Fatalf("%s status = %d, want 501", path, rec.Result().StatusCode)
		}
	}
}

// A store is wired but no enrollment cookie is present → 501: the ceremony has
// no authenticated user to bind to.
func TestHandler_MissingEnrollmentCookie_Returns501(t *testing.T) {
	mux := newCeremonyMux(t, demoHandle())
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/begin", nil) // no cookie
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Result().StatusCode)
	}
}

// The enrollment cookie is present but the session is expired/unknown (store
// returns an error) → 501.
func TestHandler_ExpiredEnrollmentSession_Returns501(t *testing.T) {
	svc, _ := newTestService(t)
	handler := NewHandler(svc).WithEnrollmentSessions(&fakeEnrollmentSessionStore{err: errors.New("expired")})
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := enrollReq(http.MethodPost, "/webauthn/register/begin", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Result().StatusCode)
	}
}

func TestHandler_FinishRegistration_NoCookie(t *testing.T) {
	mux := newCeremonyMux(t, demoHandle())
	req := enrollReq(http.MethodPost, "/webauthn/register/finish", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// No WebAuthn session cookie present → 400 session_expired.
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_FinishRegistration_InvalidSession(t *testing.T) {
	mux := newCeremonyMux(t, demoHandle())
	req := enrollReq(http.MethodPost, "/webauthn/register/finish", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "nonexistent-key"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Session key not found → 400 session_expired.
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_FinishRegistration_UnknownUser(t *testing.T) {
	mux := newCeremonyMux(t, []byte("nobody"))
	req := enrollReq(http.MethodPost, "/webauthn/register/finish", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "some-key"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Unknown user is deliberately indistinguishable from a bad request (400) to
	// prevent user-handle enumeration (docs/DESIGN.md §6.5).
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_FinishRegistration_InvalidBody(t *testing.T) {
	// Need a valid session to get past session validation and test body parsing.
	store := NewInMemoryStore()
	store.PutUser(NewUser(demoHandle(), "demo@harbor.local", "Demo", nil))
	sessions := NewInMemorySessionStore()
	svc, err := NewService(testConfig(), store, sessions)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	// Start a registration ceremony to get a valid session key.
	_, sessionKey, err := svc.BeginRegistration(context.Background(), demoHandle())
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	mux := muxForService(svc, demoHandle())

	// Send invalid JSON body.
	req := enrollReq(http.MethodPost, "/webauthn/register/finish", strings.NewReader("not-json"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionKey})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Invalid body → 400 invalid_request.
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

// TestHandler_EnrollmentSession_ReadsUserHandle verifies that when an enrollment
// session store is wired and the enrollment cookie is present, the handler reads
// the user handle from the store and drives the ceremony for that user.
func TestHandler_EnrollmentSession_ReadsUserHandle(t *testing.T) {
	store := NewInMemoryStore()
	store.PutUser(NewUser([]byte("enrolled-user"), "user@example.com", "User", nil))
	sessions := NewInMemorySessionStore()
	svc, err := NewService(testConfig(), store, sessions)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	handler := NewHandler(svc).WithEnrollmentSessions(&fakeEnrollmentSessionStore{userHandle: []byte("enrolled-user")})
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := enrollReq(http.MethodPost, "/webauthn/register/begin", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Result().StatusCode, rec.Body.String())
	}
}

// --- login ------------------------------------------------------------------

// muxWithCreds returns a mux whose service store has "demo-user" WITH a
// credential enrolled (required for BeginLogin to succeed), resolving the
// enrollment cookie to that user.
func muxWithCreds(t *testing.T) *http.ServeMux {
	t.Helper()
	store := NewInMemoryStore()
	store.PutUser(NewUser(demoHandle(), "demo@harbor.local", "Demo", []gowebauthn.Credential{{ID: []byte("cred-1"), PublicKey: []byte("pk")}}))
	svc, err := NewService(testConfig(), store, NewInMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return muxForService(svc, demoHandle())
}

func TestHandler_BeginLogin_OK(t *testing.T) {
	mux := muxWithCreds(t)
	req := enrollReq(http.MethodPost, "/webauthn/login/begin", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	var foundCookie bool
	for _, c := range res.Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			foundCookie = true
			if !c.HttpOnly {
				t.Fatal("session cookie must be HttpOnly")
			}
		}
	}
	if !foundCookie {
		t.Fatal("expected a session cookie to be set")
	}
}

func TestHandler_BeginLogin_UnknownUser(t *testing.T) {
	mux := newCeremonyMux(t, []byte("nobody"))
	req := enrollReq(http.MethodPost, "/webauthn/login/begin", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Unknown user is deliberately indistinguishable from a bad request (400) to
	// prevent user-handle enumeration (docs/DESIGN.md §6.5).
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_BeginLogin_UserWithNoCredentials(t *testing.T) {
	// The demo user in newTestService has no credentials enrolled.
	mux := newCeremonyMux(t, demoHandle())
	req := enrollReq(http.MethodPost, "/webauthn/login/begin", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// A user with no credentials cannot begin login — this maps to 400.
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_FinishLogin_NoCookie(t *testing.T) {
	mux := newCeremonyMux(t, demoHandle())
	req := enrollReq(http.MethodPost, "/webauthn/login/finish", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// No WebAuthn session cookie present → 400 session_expired.
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_FinishLogin_InvalidSession(t *testing.T) {
	mux := newCeremonyMux(t, demoHandle())
	req := enrollReq(http.MethodPost, "/webauthn/login/finish", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "nonexistent-key"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Session key not found → 400 session_expired.
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_FinishLogin_UnknownUser(t *testing.T) {
	mux := newCeremonyMux(t, []byte("nobody"))
	req := enrollReq(http.MethodPost, "/webauthn/login/finish", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "some-key"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Unknown user is deliberately indistinguishable from a bad request (400) to
	// prevent user-handle enumeration (docs/DESIGN.md §6.5).
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_FinishLogin_InvalidBody(t *testing.T) {
	// Need a valid session to get past session validation and test body parsing.
	store := NewInMemoryStore()
	store.PutUser(NewUser(demoHandle(), "demo@harbor.local", "Demo", []gowebauthn.Credential{{ID: []byte("cred-1"), PublicKey: []byte("pk")}}))
	sessions := NewInMemorySessionStore()
	svc, err := NewService(testConfig(), store, sessions)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	// Start a login ceremony to get a valid session key.
	_, sessionKey, err := svc.BeginLogin(context.Background(), demoHandle())
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	mux := muxForService(svc, demoHandle())

	// Send invalid JSON body.
	req := enrollReq(http.MethodPost, "/webauthn/login/finish", strings.NewReader("not-json"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionKey})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Invalid body → 400 invalid_request.
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}
