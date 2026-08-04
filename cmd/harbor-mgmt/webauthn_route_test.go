package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeCeremonyLimiter is an in-memory clients.RateLimiter for unit-testing
// wrapPreSessionRoute without a Redis dependency.
type fakeCeremonyLimiter struct {
	limit int
	calls int
}

func (f *fakeCeremonyLimiter) Allow(_ context.Context, _ string) (bool, time.Duration, error) {
	f.calls++
	if f.calls > f.limit {
		return false, time.Second, nil
	}
	return true, 0, nil
}

// TestWrapPreSessionRoute_CrossSiteRejectedBeforeRateLimit verifies a
// cross-site POST to a wrapped WebAuthn ceremony route is refused with no
// state change: the inner handler never runs, and the rejection does not even
// consume the abuse-gate budget.
func TestWrapPreSessionRoute_CrossSiteRejectedBeforeRateLimit(t *testing.T) {
	limiter := &fakeCeremonyLimiter{limit: 10}
	called := false
	next := func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(http.StatusOK) }
	h := wrapPreSessionRoute(next, limiter, maxWebauthnCeremonyBody)

	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/begin", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if called {
		t.Error("handler must not be invoked for a cross-site request")
	}
	if limiter.calls != 0 {
		t.Errorf("rate limiter consumed %d calls for a rejected cross-site request, want 0", limiter.calls)
	}
}

// TestWrapPreSessionRoute_RateLimitExceededReturns429 exhausts the limit and
// verifies the third-party abuse limit is actually enforced.
func TestWrapPreSessionRoute_RateLimitExceededReturns429(t *testing.T) {
	limiter := &fakeCeremonyLimiter{limit: 1}
	next := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	h := wrapPreSessionRoute(next, limiter, maxWebauthnCeremonyBody)

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/webauthn/register/begin", nil)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.RemoteAddr = "203.0.113.7:12345"
		return req
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newReq())
	if rec.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, newReq())
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429; body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 response should carry a Retry-After header")
	}
}

// TestWrapPreSessionRoute_SameOriginWithinLimitAllowed pins the happy path so
// the two added defenses (CSRF, rate limit) do not regress a legitimate call.
func TestWrapPreSessionRoute_SameOriginWithinLimitAllowed(t *testing.T) {
	limiter := &fakeCeremonyLimiter{limit: 5}
	called := false
	next := func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(http.StatusOK) }
	h := wrapPreSessionRoute(next, limiter, maxWebauthnCeremonyBody)

	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !called {
		t.Fatalf("status = %d called=%v, want 200/true", rec.Code, called)
	}
}

// TestRemoteAddrKey_DifferentIPsDifferentKeys verifies remoteAddrKey does not
// collapse distinct callers into the same rate-limit bucket, and never stores
// the raw IP as the key (docs/DESIGN.md §6.5 — no PII at rest).
func TestRemoteAddrKey_DifferentIPsDifferentKeys(t *testing.T) {
	r1 := httptest.NewRequest(http.MethodPost, "/x", nil)
	r1.RemoteAddr = "203.0.113.7:1"
	r2 := httptest.NewRequest(http.MethodPost, "/x", nil)
	r2.RemoteAddr = "203.0.113.8:1"

	k1 := remoteAddrKey(r1)
	k2 := remoteAddrKey(r2)
	if k1 == k2 {
		t.Error("different IPs must not collapse to the same rate-limit key")
	}
	if k1 == "203.0.113.7" || k1 == r1.RemoteAddr {
		t.Error("remoteAddrKey must not return the raw IP/address")
	}
}
