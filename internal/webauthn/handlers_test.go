package webauthn

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
