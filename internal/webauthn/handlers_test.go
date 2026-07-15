package webauthn

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

func newTestMux(t *testing.T) *http.ServeMux {
	t.Helper()
	svc, _ := newTestService(t)
	mux := http.NewServeMux()
	// Tests exercise the dev-only client-supplied user_id path, so enable it.
	RegisterRoutes(mux, svc, true)
	return mux
}

func demoUserParam() string {
	return base64.RawURLEncoding.EncodeToString([]byte("demo-user"))
}

func TestHandler_BeginRegistration_OK(t *testing.T) {
	mux := newTestMux(t)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/begin?user_id="+demoUserParam(), nil)
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
	mux := newTestMux(t)
	userID := base64.RawURLEncoding.EncodeToString([]byte("nobody"))
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/begin?user_id="+userID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Unknown user is deliberately indistinguishable from a bad request (400) to
	// prevent user-handle enumeration (docs/DESIGN.md §6.5).
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_BeginRegistration_MissingUserID(t *testing.T) {
	mux := newTestMux(t)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/begin", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

// CRITICAL: with the insecure user_id path disabled (production default), every
// ceremony endpoint refuses the request with 501 and never reads the
// client-supplied user_id (docs/DESIGN.md §9 — IDOR defense).
func TestHandler_UserIDPath_DisabledByDefault(t *testing.T) {
	svc, _ := newTestService(t)
	mux := http.NewServeMux()
	RegisterRoutes(mux, svc, false)

	for _, path := range []string{
		"/webauthn/register/begin",
		"/webauthn/register/finish",
		"/webauthn/login/begin",
		"/webauthn/login/finish",
	} {
		req := httptest.NewRequest(http.MethodPost, path+"?user_id="+demoUserParam(), strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Result().StatusCode != http.StatusNotImplemented {
			t.Fatalf("%s status = %d, want 501", path, rec.Result().StatusCode)
		}
	}
}

func TestHandler_FinishRegistration_NoCookie(t *testing.T) {
	mux := newTestMux(t)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish?user_id="+demoUserParam(), strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// No session cookie present → 400 session_expired.
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_FinishRegistration_InvalidSession(t *testing.T) {
	mux := newTestMux(t)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish?user_id="+demoUserParam(), strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "nonexistent-key"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Session key not found → 400 session_expired.
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_FinishRegistration_UnknownUser(t *testing.T) {
	mux := newTestMux(t)
	userID := base64.RawURLEncoding.EncodeToString([]byte("nobody"))
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish?user_id="+userID, strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "some-key"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Unknown user is deliberately indistinguishable from a bad request (400) to
	// prevent user-handle enumeration (docs/DESIGN.md §6.5).
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_FinishRegistration_MissingUserID(t *testing.T) {
	mux := newTestMux(t)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "some-key"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_FinishRegistration_InvalidUserIDEncoding(t *testing.T) {
	mux := newTestMux(t)
	// Use invalid base64 encoding.
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish?user_id=!!invalid!!", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "some-key"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_FinishRegistration_InvalidBody(t *testing.T) {
	// Need a valid session to get past session validation and test body parsing.
	store := NewInMemoryStore()
	store.PutUser(NewUser([]byte("demo-user"), "demo@harbor.local", "Demo", nil))
	sessions := NewInMemorySessionStore()
	svc, err := NewService(testConfig(), store, sessions)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	// Start a registration ceremony to get a valid session key.
	_, sessionKey, err := svc.BeginRegistration(context.Background(), []byte("demo-user"))
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	mux := http.NewServeMux()
	RegisterRoutes(mux, svc, true)

	// Send invalid JSON body.
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish?user_id="+demoUserParam(), strings.NewReader("not-json"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionKey})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Invalid body → 400 invalid_request.
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

// newTestMuxWithCreds returns a mux with a service whose store has a user with
// credentials enrolled (required for BeginLogin to succeed).
func newTestMuxWithCreds(t *testing.T) *http.ServeMux {
	t.Helper()
	store := NewInMemoryStore()
	store.PutUser(NewUser([]byte("demo-user"), "demo@harbor.local", "Demo", []gowebauthn.Credential{{ID: []byte("cred-1"), PublicKey: []byte("pk")}}))
	svc, err := NewService(testConfig(), store, NewInMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	mux := http.NewServeMux()
	RegisterRoutes(mux, svc, true)
	return mux
}

func TestHandler_BeginLogin_OK(t *testing.T) {
	mux := newTestMuxWithCreds(t)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin?user_id="+demoUserParam(), nil)
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
	mux := newTestMux(t)
	userID := base64.RawURLEncoding.EncodeToString([]byte("nobody"))
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin?user_id="+userID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Unknown user is deliberately indistinguishable from a bad request (400) to
	// prevent user-handle enumeration (docs/DESIGN.md §6.5).
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_BeginLogin_UserWithNoCredentials(t *testing.T) {
	// The demo user in newTestMux has no credentials enrolled.
	mux := newTestMux(t)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin?user_id="+demoUserParam(), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// A user with no credentials cannot begin login — this maps to 400.
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_BeginLogin_MissingUserID(t *testing.T) {
	mux := newTestMux(t)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_BeginLogin_InvalidUserIDEncoding(t *testing.T) {
	mux := newTestMux(t)
	// Use invalid base64 encoding.
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin?user_id=!!invalid!!", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_FinishLogin_NoCookie(t *testing.T) {
	mux := newTestMux(t)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish?user_id="+demoUserParam(), strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// No session cookie present → 400 session_expired.
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_FinishLogin_InvalidSession(t *testing.T) {
	mux := newTestMux(t)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish?user_id="+demoUserParam(), strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "nonexistent-key"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Session key not found → 400 session_expired.
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_FinishLogin_UnknownUser(t *testing.T) {
	mux := newTestMux(t)
	userID := base64.RawURLEncoding.EncodeToString([]byte("nobody"))
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish?user_id="+userID, strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "some-key"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Unknown user is deliberately indistinguishable from a bad request (400) to
	// prevent user-handle enumeration (docs/DESIGN.md §6.5).
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_FinishLogin_MissingUserID(t *testing.T) {
	mux := newTestMux(t)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "some-key"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestHandler_FinishLogin_InvalidUserIDEncoding(t *testing.T) {
	mux := newTestMux(t)
	// Use invalid base64 encoding.
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish?user_id=!!invalid!!", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "some-key"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

// fakeEnrollmentSessionStore is an in-memory enrollment session store for tests.
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

// TestHandler_EnrollmentSession_ReadsUserHandle verifies that when an enrollment
// session store is wired and the enrollment cookie is present, the handler reads
// the user handle from the store instead of requiring the insecure query param.
func TestHandler_EnrollmentSession_ReadsUserHandle(t *testing.T) {
	store := NewInMemoryStore()
	store.PutUser(NewUser([]byte("enrolled-user"), "user@example.com", "User", nil))
	sessions := NewInMemorySessionStore()
	svc, err := NewService(testConfig(), store, sessions)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	// Wire the handler with an enrollment session store that returns "enrolled-user".
	fakeEnroll := &fakeEnrollmentSessionStore{userHandle: []byte("enrolled-user")}
	handler := NewHandler(svc, false).WithEnrollmentSessions(fakeEnroll)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /webauthn/register/begin", handler.BeginRegistration)

	// No user_id query param — the handler should read from the enrollment cookie.
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/begin", nil)
	req.AddCookie(&http.Cookie{Name: enrollmentCookieName, Value: "session-key"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Should succeed (200) because the enrollment session provides the user handle.
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Result().StatusCode, rec.Body.String())
	}
}

// TestHandler_EnrollmentSession_FallbackTo501 verifies that when the enrollment
// cookie is absent and allowInsecureUserID is false, the handler returns 501.
func TestHandler_EnrollmentSession_FallbackTo501(t *testing.T) {
	store := NewInMemoryStore()
	store.PutUser(NewUser([]byte("user"), "u@e.com", "U", nil))
	sessions := NewInMemorySessionStore()
	svc, err := NewService(testConfig(), store, sessions)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	// Enrollment session store wired, but no cookie present.
	fakeEnroll := &fakeEnrollmentSessionStore{userHandle: []byte("user")}
	handler := NewHandler(svc, false).WithEnrollmentSessions(fakeEnroll)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /webauthn/register/begin", handler.BeginRegistration)

	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/begin", nil)
	// No enrollment cookie set.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Should fall through to 501 because no cookie and insecure path disabled.
	if rec.Result().StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Result().StatusCode)
	}
}

func TestHandler_FinishLogin_InvalidBody(t *testing.T) {
	// Need a valid session to get past session validation and test body parsing.
	store := NewInMemoryStore()
	store.PutUser(NewUser([]byte("demo-user"), "demo@harbor.local", "Demo", []gowebauthn.Credential{{ID: []byte("cred-1"), PublicKey: []byte("pk")}}))
	sessions := NewInMemorySessionStore()
	svc, err := NewService(testConfig(), store, sessions)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	// Start a login ceremony to get a valid session key.
	_, sessionKey, err := svc.BeginLogin(context.Background(), []byte("demo-user"))
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	mux := http.NewServeMux()
	RegisterRoutes(mux, svc, true)

	// Send invalid JSON body.
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish?user_id="+demoUserParam(), strings.NewReader("not-json"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionKey})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Invalid body → 400 invalid_request.
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}
