package oidcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/gen/openapi"
	"github.com/harbor-auth/harbor/internal/telemetry"
	dto "github.com/prometheus/client_model/go"
)

// stubLimiter is a controllable clients.RateLimiter for tests that need a
// specific (allowed, retryAfter, err) response or want to capture the exact
// keys the middleware derives. The zero value allows every request.
type stubLimiter struct {
	allowed    bool
	retryAfter time.Duration
	err        error

	mu   sync.Mutex
	keys []string
}

func (s *stubLimiter) Allow(_ context.Context, key string) (bool, time.Duration, error) {
	s.mu.Lock()
	s.keys = append(s.keys, key)
	s.mu.Unlock()
	return s.allowed, s.retryAfter, s.err
}

func (s *stubLimiter) lastKey() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.keys) == 0 {
		return ""
	}
	return s.keys[len(s.keys)-1]
}

// okNext is a next handler that records invocation and writes 200 OK with a
// small body, so tests can distinguish "passed through" from "short-circuited".
func okNext(called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// rateLimitReq builds a request to a known-region host so any region-labelled
// metric resolves deterministically. clientID (when non-empty) is sent via HTTP
// Basic auth; remoteAddr (when non-empty) overrides the transport address.
func rateLimitReq(clientID, remoteAddr string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	req.Host = "eu.harbor.id"
	if clientID != "" {
		req.SetBasicAuth(clientID, "secret")
	}
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	return req
}

// counterSumByEndpoint returns the sum of a counter metric's series whose
// `endpoint` label equals endpoint, across all region values. Tests compare
// before/after deltas so the package-shared registry state does not matter.
func counterSumByEndpoint(t *testing.T, name string, endpoint telemetry.EndpointName) float64 {
	t.Helper()
	families, err := telemetry.Registry().Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	var total float64
	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if hasLabel(m.GetLabel(), "endpoint", string(endpoint)) {
				total += m.GetCounter().GetValue()
			}
		}
	}
	return total
}

func hasLabel(labels []*dto.LabelPair, name, value string) bool {
	for _, lp := range labels {
		if lp.GetName() == name && lp.GetValue() == value {
			return true
		}
	}
	return false
}

// TestRateLimitMiddleware_UnderLimitPassesThrough verifies that requests below
// the limit are forwarded to the next handler untouched.
func TestRateLimitMiddleware_UnderLimitPassesThrough(t *testing.T) {
	lim := clients.NewMemoryRateLimiter(clients.RateLimiterConfig{Limit: 5, Window: time.Minute})
	h := RateLimitMiddleware(RateLimitConfig{
		Limiter:  lim,
		Endpoint: telemetry.EndpointToken,
		Window:   time.Minute,
	})(okNextHandler())

	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, rateLimitReq("client-under", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i, rec.Code, http.StatusOK)
		}
		if rec.Body.String() != "ok" {
			t.Fatalf("request %d: body = %q, want %q", i, rec.Body.String(), "ok")
		}
	}
}

// okNextHandler is a convenience next handler that always writes 200 OK + "ok".
func okNextHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// TestRateLimitMiddleware_OverLimitReturns429 verifies that once the limit is
// exhausted the middleware short-circuits with 429, a non-negative Retry-After
// header, the rate_limited error envelope, and does NOT call the next handler.
func TestRateLimitMiddleware_OverLimitReturns429(t *testing.T) {
	lim := clients.NewMemoryRateLimiter(clients.RateLimiterConfig{Limit: 2, Window: time.Minute})
	nextCalled := false
	h := RateLimitMiddleware(RateLimitConfig{
		Limiter:  lim,
		Endpoint: telemetry.EndpointToken,
		Window:   time.Minute,
	})(okNext(&nextCalled))

	// Exhaust the limit (2 allowed).
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, rateLimitReq("client-over", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("warmup %d: status = %d, want 200", i, rec.Code)
		}
	}

	// Third request is over the limit.
	nextCalled = false
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, rateLimitReq("client-over", ""))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if nextCalled {
		t.Fatal("next handler was called on a rate-limited request; must short-circuit")
	}

	// Retry-After must be present and a non-negative integer within the window.
	ra := rec.Header().Get("Retry-After")
	if ra == "" {
		t.Fatal("missing Retry-After header on 429")
	}
	secs, err := strconv.Atoi(ra)
	if err != nil {
		t.Fatalf("Retry-After %q is not an integer: %v", ra, err)
	}
	if secs < 0 {
		t.Fatalf("Retry-After = %d, must be non-negative", secs)
	}
	if secs > 60 {
		t.Fatalf("Retry-After = %d, must be clamped to window (60s)", secs)
	}

	var body openapi.Error
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode 429 body: %v", err)
	}
	if body.Code != "rate_limited" {
		t.Fatalf("error code = %q, want %q", body.Code, "rate_limited")
	}
}

// TestRateLimitMiddleware_PerClientBucketsIndependent verifies that exhausting
// one client's bucket does not affect another client's bucket.
func TestRateLimitMiddleware_PerClientBucketsIndependent(t *testing.T) {
	lim := clients.NewMemoryRateLimiter(clients.RateLimiterConfig{Limit: 2, Window: time.Minute})
	h := RateLimitMiddleware(RateLimitConfig{
		Limiter:  lim,
		Endpoint: telemetry.EndpointToken,
		Window:   time.Minute,
	})(okNextHandler())

	// client-a exhausts its bucket.
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, rateLimitReq("client-a", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("client-a warmup %d: status = %d, want 200", i, rec.Code)
		}
	}
	recA := httptest.NewRecorder()
	h.ServeHTTP(recA, rateLimitReq("client-a", ""))
	if recA.Code != http.StatusTooManyRequests {
		t.Fatalf("client-a over-limit status = %d, want 429", recA.Code)
	}

	// client-b must be unaffected.
	recB := httptest.NewRecorder()
	h.ServeHTTP(recB, rateLimitReq("client-b", ""))
	if recB.Code != http.StatusOK {
		t.Fatalf("client-b status = %d, want 200 (independent bucket)", recB.Code)
	}
}

// TestRateLimitMiddleware_PerIPBucketsIndependent verifies that anonymous
// requests bucket per source IP, and exhausting one IP does not affect another.
func TestRateLimitMiddleware_PerIPBucketsIndependent(t *testing.T) {
	lim := clients.NewMemoryRateLimiter(clients.RateLimiterConfig{Limit: 2, Window: time.Minute})
	h := RateLimitMiddleware(RateLimitConfig{
		Limiter:  lim,
		Endpoint: telemetry.EndpointToken,
		Window:   time.Minute,
	})(okNextHandler())

	// IP .1 exhausts its bucket (no Basic auth → keyed by IP).
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, rateLimitReq("", "10.0.0.1:1111"))
		if rec.Code != http.StatusOK {
			t.Fatalf("ip1 warmup %d: status = %d, want 200", i, rec.Code)
		}
	}
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, rateLimitReq("", "10.0.0.1:1111"))
	if rec1.Code != http.StatusTooManyRequests {
		t.Fatalf("ip1 over-limit status = %d, want 429", rec1.Code)
	}

	// A different IP must be unaffected.
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, rateLimitReq("", "10.0.0.2:2222"))
	if rec2.Code != http.StatusOK {
		t.Fatalf("ip2 status = %d, want 200 (independent bucket)", rec2.Code)
	}
}

// TestRateLimitMiddleware_ClientIDPreferredOverIP verifies the key uses the
// authenticated client_id when Basic auth is present, and the source IP
// otherwise. It inspects the exact keys the middleware hands the limiter.
func TestRateLimitMiddleware_ClientIDPreferredOverIP(t *testing.T) {
	stub := &stubLimiter{allowed: true}
	h := RateLimitMiddleware(RateLimitConfig{
		Limiter:  stub,
		Endpoint: telemetry.EndpointToken,
		Window:   time.Minute,
	})(okNextHandler())

	// Authenticated → key by client_id.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, rateLimitReq("acme-rp", "10.0.0.9:5555"))
	if got, want := stub.lastKey(), "token:acme-rp"; got != want {
		t.Fatalf("authenticated key = %q, want %q", got, want)
	}

	// Anonymous → key by IP.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, rateLimitReq("", "10.0.0.9:5555"))
	if got, want := stub.lastKey(), "token:10.0.0.9"; got != want {
		t.Fatalf("anonymous key = %q, want %q", got, want)
	}
}

// TestRateLimitMiddleware_TrustedForwardedHeader verifies that the configured
// trusted forwarded header supplies the client IP for the anonymous bucket,
// using the leftmost (original client) address.
func TestRateLimitMiddleware_TrustedForwardedHeader(t *testing.T) {
	stub := &stubLimiter{allowed: true}
	h := RateLimitMiddleware(RateLimitConfig{
		Limiter:                stub,
		Endpoint:               telemetry.EndpointToken,
		Window:                 time.Minute,
		TrustedForwardedHeader: "X-Forwarded-For",
	})(okNextHandler())

	req := rateLimitReq("", "10.9.9.9:1234")
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.9.9.9")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got, want := stub.lastKey(), "token:203.0.113.7"; got != want {
		t.Fatalf("forwarded key = %q, want %q", got, want)
	}
}

// TestRateLimitMiddleware_FailOpenOnError verifies that a limiter error fails
// OPEN: the request is allowed through, a PII-free warning is logged, and the
// rate_limiter_unavailable metric is incremented.
func TestRateLimitMiddleware_FailOpenOnError(t *testing.T) {
	stub := &stubLimiter{err: errors.New("redis down")}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	nextCalled := false
	h := RateLimitMiddleware(RateLimitConfig{
		Limiter:  stub,
		Endpoint: telemetry.EndpointIntrospect,
		Window:   time.Minute,
		Logger:   logger,
	})(okNext(&nextCalled))

	before := counterSumByEndpoint(t, "harbor_oidc_rate_limiter_unavailable_total", telemetry.EndpointIntrospect)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, rateLimitReq("client-x", ""))

	// Fail OPEN: request allowed through to the next handler.
	if !nextCalled {
		t.Fatal("next handler not called on limiter error; must fail open")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 on fail-open", rec.Code)
	}

	// Warning logged with the aggregate event marker and NO PII (no client_id).
	logged := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("rate_limiter_unavailable")) {
		t.Fatalf("expected fail-open warning with event=rate_limiter_unavailable, got: %q", logged)
	}
	if bytes.Contains(buf.Bytes(), []byte("client-x")) {
		t.Fatalf("fail-open log leaked the client_id (PII): %q", logged)
	}

	// Metric incremented for this endpoint.
	after := counterSumByEndpoint(t, "harbor_oidc_rate_limiter_unavailable_total", telemetry.EndpointIntrospect)
	if after-before < 1 {
		t.Fatalf("rate_limiter_unavailable metric did not increment: before=%v after=%v", before, after)
	}
}

// TestRateLimitMiddleware_DeniedEmitsRateLimitedMetric verifies a 429 increments
// the aggregate harbor_oidc_rate_limited_total counter for the endpoint.
func TestRateLimitMiddleware_DeniedEmitsRateLimitedMetric(t *testing.T) {
	stub := &stubLimiter{allowed: false, retryAfter: 5 * time.Second}
	h := RateLimitMiddleware(RateLimitConfig{
		Limiter:  stub,
		Endpoint: telemetry.EndpointAuthorize,
		Window:   time.Minute,
	})(okNextHandler())

	before := counterSumByEndpoint(t, "harbor_oidc_rate_limited_total", telemetry.EndpointAuthorize)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, rateLimitReq("client-y", ""))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "5" {
		t.Fatalf("Retry-After = %q, want %q", got, "5")
	}

	after := counterSumByEndpoint(t, "harbor_oidc_rate_limited_total", telemetry.EndpointAuthorize)
	if after-before < 1 {
		t.Fatalf("rate_limited metric did not increment: before=%v after=%v", before, after)
	}
}

// TestRateLimitMiddleware_NilLimiterPassthrough verifies that a nil limiter
// disables rate limiting entirely (transparent passthrough).
func TestRateLimitMiddleware_NilLimiterPassthrough(t *testing.T) {
	nextCalled := false
	h := RateLimitMiddleware(RateLimitConfig{
		Limiter:  nil,
		Endpoint: telemetry.EndpointToken,
		Window:   time.Minute,
	})(okNext(&nextCalled))

	for i := 0; i < 100; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, rateLimitReq("client-nil", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 (no limiter → passthrough)", i, rec.Code)
		}
	}
	if !nextCalled {
		t.Fatal("next handler not called with nil limiter")
	}
}

// TestRetryAfterSeconds verifies the Retry-After clamping/rounding logic:
// clamped to [0, window] and rounded up to whole delta-seconds.
func TestRetryAfterSeconds(t *testing.T) {
	window := time.Minute
	cases := []struct {
		name       string
		retryAfter time.Duration
		want       int
	}{
		{"zero", 0, 0},
		{"negative clamps to zero", -5 * time.Second, 0},
		{"sub-second rounds up", 500 * time.Millisecond, 1},
		{"exact seconds", 30 * time.Second, 30},
		{"fractional rounds up", 30*time.Second + 1*time.Millisecond, 31},
		{"over window clamps", 90 * time.Second, 60},
		{"at window", 60 * time.Second, 60},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryAfterSeconds(tc.retryAfter, window); got != tc.want {
				t.Fatalf("retryAfterSeconds(%v, %v) = %d, want %d", tc.retryAfter, window, got, tc.want)
			}
			if got := retryAfterSeconds(tc.retryAfter, window); got < 0 {
				t.Fatalf("retryAfterSeconds returned negative: %d", got)
			}
		})
	}
}

// TestRateLimitInterfaceCompliance is a compile-time-ish guard that the stub and
// the real limiters satisfy clients.RateLimiter (used throughout these tests).
func TestRateLimitInterfaceCompliance(t *testing.T) {
	var _ clients.RateLimiter = (*stubLimiter)(nil)
	var _ clients.RateLimiter = (*clients.MemoryRateLimiter)(nil)
}
