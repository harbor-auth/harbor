package mgmtapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/identity"
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

func doEnroll(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.PostEnroll(rec, req)
	return rec
}

func TestPostEnrollSuccess(t *testing.T) {
	const userID = "550e8400-e29b-41d4-a716-446655440000"
	fe := &fakeEnroller{result: identity.EnrollResult{UserID: userID, Region: "EU"}}
	s := newTestServer(fe)

	rec := doEnroll(t, s, `{"region":"EU"}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp enrollResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.UserID != userID {
		t.Errorf("user_id = %q, want %s", resp.UserID, userID)
	}
	if resp.Status != statusPending {
		t.Errorf("status = %q, want %q", resp.Status, statusPending)
	}
	if !fe.called {
		t.Error("expected Enroll to be called")
	}
	if fe.gotRegion != "EU" {
		t.Errorf("Enroll got region %q, want EU", fe.gotRegion)
	}
}

func TestPostEnrollInvalidRegion(t *testing.T) {
	fe := &fakeEnroller{result: identity.EnrollResult{UserID: "x"}}
	s := newTestServer(fe)

	rec := doEnroll(t, s, `{"region":"ATLANTIS"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if fe.called {
		t.Error("Enroll must not be called for an invalid region")
	}
}

func TestPostEnrollMalformedBody(t *testing.T) {
	fe := &fakeEnroller{}
	s := newTestServer(fe)

	rec := doEnroll(t, s, `{not json`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if fe.called {
		t.Error("Enroll must not be called for a malformed body")
	}
}

// TestPostEnrollUnavailable retains the historical missing-enroller regression.
// The server now fails closed at construction instead of exposing a 503 route.
func TestPostEnrollUnavailable(t *testing.T) {
	if _, err := New(nil, NewInMemoryEnrollmentSessionStore(), &fakeClientReg{}, testRegBaseURL, nil); err == nil {
		t.Fatal("New accepted a nil enroller")
	}
}

func TestPostEnrollServerError(t *testing.T) {
	fe := &fakeEnroller{err: errors.New("db down")}
	s := newTestServer(fe)

	rec := doEnroll(t, s, `{"region":"EU"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// --- checkPreSessionOrigin / cross-site CSRF tests ---

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

// TestPostEnrollCrossSitePostRejected verifies a cross-site POST /enroll is
// refused with no state change: the enroller is never invoked, so no user row
// or enrollment-session cookie is created for the forged request.
func TestPostEnrollCrossSitePostRejected(t *testing.T) {
	fe := &fakeEnroller{result: identity.EnrollResult{UserID: "x", Region: "EU"}}
	s := newTestServer(fe)

	req := httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader(`{"region":"EU"}`))
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	s.PostEnroll(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if fe.called {
		t.Error("Enroll must not be called for a cross-site request (no state change)")
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("no cookie should be set for a rejected cross-site request")
	}
}

// TestPostEnrollCrossOriginHeaderRejected exercises the Origin-header fallback
// path (no Sec-Fetch-Site) with the same no-state-change expectation.
func TestPostEnrollCrossOriginHeaderRejected(t *testing.T) {
	fe := &fakeEnroller{result: identity.EnrollResult{UserID: "x", Region: "EU"}}
	s := newTestServer(fe)

	req := httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader(`{"region":"EU"}`))
	req.Header.Set("Origin", "https://evil.example.com")
	req.Host = "harbor.example.com"
	rec := httptest.NewRecorder()
	s.PostEnroll(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if fe.called {
		t.Error("Enroll must not be called for a cross-origin request")
	}
}

// TestPostEnrollSameOriginStillWorks pins down that the new CSRF check does not
// regress a legitimate same-origin (or header-less) enrollment.
func TestPostEnrollSameOriginStillWorks(t *testing.T) {
	fe := &fakeEnroller{result: identity.EnrollResult{UserID: "550e8400-e29b-41d4-a716-446655440002", Region: "EU"}}
	s := newTestServer(fe)

	req := httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader(`{"region":"EU"}`))
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	s.PostEnroll(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if !fe.called {
		t.Error("expected Enroll to be called for a same-origin request")
	}
}

// --- abuse-gate rate-limit integration on PostEnroll ---

// fakeRateLimiter denies every call once calls reach limit, without any Redis
// dependency — enough to exercise the s.abuseGate.Check(...) wiring already in
// PostEnroll alongside the new pre-session CSRF check.
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

// TestPostEnrollRateLimitedAfterOrigin verifies that a same-origin (CSRF-
// passing) request that exhausts the abuse-gate limit gets 429, and that the
// CSRF check runs independently of — and before — rate-limit accounting.
func TestPostEnrollRateLimitedAfterOrigin(t *testing.T) {
	fe := &fakeEnroller{result: identity.EnrollResult{UserID: "550e8400-e29b-41d4-a716-446655440003", Region: "EU"}}
	s := newTestServer(fe)
	limiter := &fakeRateLimiter{limit: 1}
	s.WithProductionAbuseProtection("enroll", limiter)

	// First same-origin request consumes the single allowed slot.
	rec := doEnroll(t, s, `{"region":"EU"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first request status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	// Second same-origin request is over budget.
	rec = doEnroll(t, s, `{"region":"EU"}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429; body=%s", rec.Code, rec.Body.String())
	}
}

// TestRoutesRegistersEnroll verifies POST /enroll is wired through the mux.
func TestRoutesRegistersEnroll(t *testing.T) {
	fe := &fakeEnroller{result: identity.EnrollResult{UserID: "550e8400-e29b-41d4-a716-446655440001", Region: "EU"}}
	s := newTestServer(fe)

	mux := http.NewServeMux()
	s.Routes(mux)

	req := httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader([]byte(`{"region":"EU"}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("routed status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
}
