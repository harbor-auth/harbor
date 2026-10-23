package mgmtapi

import (
	"context"
	"errors"
	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/harbor-auth/harbor/internal/signup"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeEnroller is an in-memory Enroller for handler tests.
type fakeEnroller struct {
	result    identity.EnrollResult
	err       error
	gotRegion string
	called    bool
}

func (f *fakeEnroller) Enroll(_ context.Context, rawRegion string) (identity.EnrollResult, error) {
	f.called = true
	f.gotRegion = rawRegion
	return f.result, f.err
}

func TestCheckPreSessionOrigin(t *testing.T) {
	cases := []struct {
		name    string
		sfs     string
		origin  string
		host    string
		wantErr bool
	}{
		{"same-origin Sec-Fetch-Site", "same-origin", "", "", false},
		{"same-site Sec-Fetch-Site", "same-site", "", "", false},
		{"none Sec-Fetch-Site", "none", "", "", false},
		{"cross-site Sec-Fetch-Site", "cross-site", "", "", true},
		{"same origin via Origin fallback", "", "https://harbor.example.com", "harbor.example.com", false},
		{"cross origin via Origin fallback", "", "https://evil.example.com", "harbor.example.com", true},
		{"opaque null origin", "", "null", "harbor.example.com", true},
		{"malformed origin", "", "not-a-url", "harbor.example.com", true},
		{"no headers at all", "", "", "harbor.example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/enroll", nil)
			if tc.sfs != "" {
				r.Header.Set("Sec-Fetch-Site", tc.sfs)
			}
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			r.Host = tc.host
			err := checkPreSessionOrigin(r)
			if (err != nil) != tc.wantErr {
				t.Errorf("checkPreSessionOrigin() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

type fakeRateLimiter struct {
	limit int
	calls int
}

func (f *fakeRateLimiter) Allow(_ context.Context, _ string) (bool, time.Duration, error) {
	f.calls++
	if f.calls > f.limit {
		return false, time.Second, nil
	}
	return true, 0, nil
}

type fakeEmailSignup struct {
	started, finished bool
	returnTo          string
	err               error
}

func (f *fakeEmailSignup) Start(_ context.Context, email, reg, returnTo string) (string, error) {
	f.started = true
	f.returnTo = returnTo
	return strings.Repeat("a", 64), f.err
}
func (f *fakeEmailSignup) Finish(_ context.Context, key, code string) (identity.EnrollResult, string, error) {
	f.finished = true
	return identity.EnrollResult{UserID: "550e8400-e29b-41d4-a716-446655440000", Region: "EU"}, f.returnTo, f.err
}
func signupRequest(s *Server, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	s.Routes(mux)
	mux.ServeHTTP(rec, req)
	return rec
}
func TestEmailSignupStartDoesNotEnroll(t *testing.T) {
	legacy := &fakeEnroller{}
	flow := &fakeEmailSignup{}
	s := newTestServer(legacy).WithEmailSignup(flow)
	rec := signupRequest(s, "/enroll", `{"email":"me@example.com","region":"EU"}`, &http.Cookie{Name: SignupReturnToCookieName, Value: "/dashboard/next"})
	if rec.Code != 202 || !flow.started || legacy.called {
		t.Fatalf("unexpected start: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "user_id") {
		t.Fatal("start exposed an account")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != SignupVerificationCookieName || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("cookies: %+v", cookies)
	}
	if flow.returnTo != "/dashboard/next" {
		t.Fatal("lost return destination")
	}
	// Finish must use the captured destination, not a subsequently changed cookie.
	done := signupRequest(s, "/enroll/verify", `{"code":"12345678"}`, cookies[0], &http.Cookie{Name: SignupReturnToCookieName, Value: "/changed"})
	if done.Code != 201 || !flow.finished {
		t.Fatalf("verify: %d %s", done.Code, done.Body)
	}
	var handoff *http.Cookie
	for _, c := range done.Result().Cookies() {
		if c.Name == EnrollmentSessionCookieName {
			handoff = c
		}
	}
	if handoff == nil {
		t.Fatal("missing enrollment session")
	}
	_, recovery, returnTo, err := s.sessions.UserHandle(context.Background(), handoff.Value)
	if err != nil || recovery || returnTo != "/dashboard/next" {
		t.Fatalf("bad handoff: %v %q %v", recovery, returnTo, err)
	}
}
func TestEmailSignupRejectsUnverifiedAndInvalidRequests(t *testing.T) {
	for _, body := range []string{`{"region":"EU"}`, `{"email":"bad","region":"EU"}`, `{"email":"me@example.com","region":"bad"}`, `{"email":"me@example.com","region":"EU","user_id":"forged"}`, `{} {}`, `{broken`} {
		flow := &fakeEmailSignup{}
		s := newTestServer(nil).WithEmailSignup(flow)
		rec := signupRequest(s, "/enroll", body)
		if rec.Code != 400 || flow.started || flow.finished {
			t.Fatalf("accepted %s: %d", body, rec.Code)
		}
	}
	flow := &fakeEmailSignup{}
	s := newTestServer(nil).WithEmailSignup(flow)
	rec := signupRequest(s, "/enroll/verify", `{"code":"12345678"}`)
	if rec.Code != 400 || flow.finished {
		t.Fatal("verification accepted without browser cookie")
	}
	rec = signupRequest(newTestServer(nil), "/enroll", `{"email":"me@example.com","region":"EU"}`)
	if rec.Code != 503 {
		t.Fatal("unconfigured signup did not fail closed")
	}
	rec = signupRequest(s.WithSignupRegion("US"), "/enroll", `{"email":"me@example.com","region":"EU"}`)
	if rec.Code != 400 || flow.started {
		t.Fatal("accepted another deployment's region")
	}
}
func TestEmailSignupErrorPaths(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
	}{{signup.ErrInvalidCode, 400}, {identity.ErrIdentifierExists, 409}, {errors.New("db failure"), 500}} {
		flow := &fakeEmailSignup{err: tc.err}
		s := newTestServer(nil).WithEmailSignup(flow)
		rec := signupRequest(s, "/enroll/verify", `{"code":"12345678"}`, &http.Cookie{Name: SignupVerificationCookieName, Value: strings.Repeat("a", 64)})
		if rec.Code != tc.status {
			t.Fatalf("got %d want %d", rec.Code, tc.status)
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == EnrollmentSessionCookieName {
				t.Fatal("failed verification minted credential authority")
			}
		}
	}
	for _, tc := range []struct {
		err    error
		status int
	}{{signup.ErrRateLimited, 429}, {errors.New("smtp recipient me@example.com failed"), 503}} {
		rec := signupRequest(newTestServer(nil).WithEmailSignup(&fakeEmailSignup{err: tc.err}), "/enroll", `{"email":"me@example.com","region":"EU"}`)
		if rec.Code != tc.status || strings.Contains(rec.Body.String(), "me@example.com") {
			t.Fatalf("unexpected failure %d %s", rec.Code, rec.Body)
		}
	}
}
func TestEmailSignupOriginAndRateGates(t *testing.T) {
	for _, path := range []string{"/enroll", "/enroll/verify"} {
		flow := &fakeEmailSignup{}
		s := newTestServer(nil).WithEmailSignup(flow)
		mux := http.NewServeMux()
		s.Routes(mux)
		req := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 403 || flow.started || flow.finished {
			t.Fatal("cross-site signup accepted")
		}
		s.WithProductionAbuseProtection("enroll", &fakeRateLimiter{limit: 0})
		rec = signupRequest(s, path, `{}`)
		if rec.Code != 429 || flow.started || flow.finished {
			t.Fatal("rate limit bypass")
		}
	}
}
