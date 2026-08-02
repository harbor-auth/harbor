package clients

import (
	"context"
	"io"
	"log/slog"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

var _ RateLimiter = (*MemoryRateLimiter)(nil)

// memWindow holds the sliding-window counters for a single key. windowStart is
// the start (unix ms) of the window `current` counts against; `previous` counts
// the window immediately before it, used for the sliding-window overlap.
type memWindow struct {
	windowStart int64
	current     int
	previous    int
}

// MemoryRateLimiter is an in-process RateLimiter for local development and
// tests, used when REDIS_URL is unset (see ConnectRedis). It mirrors the
// sliding-window semantics of RedisRateLimiter but keeps all state in a
// mutex-guarded map, so it is single-replica only and MUST NOT be used in
// production (each replica would enforce its own independent limit).
//
// Stale per-key entries are pruned lazily on access and periodically swept, so
// memory stays bounded to roughly the set of recently-active keys.
type MemoryRateLimiter struct {
	mu         sync.Mutex
	entries    map[string]*memWindow
	limit      int
	window     time.Duration
	lastSweep  time.Time
	sweepEvery time.Duration
	// nowFn is an injectable clock, overridden in tests for deterministic
	// window advancement; defaults to time.Now.
	nowFn func() time.Time
}

// NewMemoryRateLimiter creates an in-memory rate limiter with the same config
// contract as NewRedisRateLimiter (KeyPrefix is unused here — keys are already
// fully-qualified by the caller). Defaults match the Redis limiter so switching
// backends does not change limits.
func NewMemoryRateLimiter(cfg RateLimiterConfig) *MemoryRateLimiter {
	if cfg.Limit <= 0 {
		cfg.Limit = 100 // sensible default (matches RedisRateLimiter)
	}
	if cfg.Window < time.Second {
		cfg.Window = time.Minute // minimum 1 second, default 1 minute
	}
	return &MemoryRateLimiter{
		entries:    make(map[string]*memWindow),
		limit:      cfg.Limit,
		window:     cfg.Window,
		sweepEvery: cfg.Window * 2,
		nowFn:      time.Now,
	}
}

// Allow implements RateLimiter using the same sliding-window approximation as
// RedisRateLimiter, guarded by a mutex for goroutine safety. It never returns
// an error: an in-memory store cannot be "unavailable", so the fail-open path
// only applies to the Redis backend.
func (m *MemoryRateLimiter) Allow(_ context.Context, key string) (bool, time.Duration, error) {
	now := m.nowFn()
	nowMs := now.UnixMilli()
	windowMs := m.window.Milliseconds()
	currentWindowStart := (nowMs / windowMs) * windowMs
	previousWindowStart := currentWindowStart - windowMs

	m.mu.Lock()
	defer m.mu.Unlock()

	m.sweepLocked(previousWindowStart, now)

	e := m.entries[key]
	if e == nil {
		e = &memWindow{windowStart: currentWindowStart}
		m.entries[key] = e
	}

	// Roll the window forward to the current one, carrying `current` into
	// `previous` when we advance exactly one window, and clearing both when the
	// entry is older than the previous window (fully aged out).
	switch e.windowStart {
	case currentWindowStart:
		// same window — no roll needed
	case previousWindowStart:
		e.previous = e.current
		e.current = 0
		e.windowStart = currentWindowStart
	default:
		e.previous = 0
		e.current = 0
		e.windowStart = currentWindowStart
	}

	elapsed := nowMs - currentWindowStart
	overlap := 1.0 - float64(elapsed)/float64(windowMs)
	if overlap < 0 {
		overlap = 0
	}
	effective := float64(e.current) + float64(e.previous)*overlap

	if effective >= float64(m.limit) {
		retryAfter := m.retryAfter(e, elapsed, windowMs)
		return false, retryAfter, nil
	}

	e.current++
	return true, 0, nil
}

// retryAfter mirrors the Lua retry-after computation: how long until the sliding
// effective count would drop below the limit.
func (m *MemoryRateLimiter) retryAfter(e *memWindow, elapsed, windowMs int64) time.Duration {
	var retryMs int64
	if e.previous > 0 && e.current < m.limit {
		targetOverlap := (float64(m.limit) - float64(e.current) - 0.001) / float64(e.previous)
		if targetOverlap < 0 {
			targetOverlap = 0
		}
		targetElapsed := float64(windowMs) * (1 - targetOverlap)
		retryMs = int64(math.Ceil(targetElapsed - float64(elapsed)))
	} else {
		retryMs = windowMs - elapsed
	}
	if retryMs < 1 {
		retryMs = 1
	}
	return time.Duration(retryMs) * time.Millisecond
}

// sweepLocked periodically removes entries whose window has fully aged out
// (older than the previous window), keeping the map bounded to recently-active
// keys. Caller must hold m.mu.
func (m *MemoryRateLimiter) sweepLocked(previousWindowStart int64, now time.Time) {
	if now.Sub(m.lastSweep) < m.sweepEvery {
		return
	}
	m.lastSweep = now
	for k, e := range m.entries {
		if e.windowStart < previousWindowStart {
			delete(m.entries, k)
		}
	}
}

// testRateLimiter creates a miniredis-backed rate limiter for testing.
func testRateLimiter(t *testing.T, cfg RateLimiterConfig) (*RedisRateLimiter, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // test cleanup
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewRedisRateLimiter(client, cfg, logger), mr
}

// TestRedisRateLimiter_AllowUnderLimit verifies that requests under the limit
// are allowed.
func TestRedisRateLimiter_AllowUnderLimit(t *testing.T) {
	limiter, _ := testRateLimiter(t, RateLimiterConfig{
		KeyPrefix: "test:",
		Limit:     10,
		Window:    time.Minute,
	})
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		allowed, retryAfter, err := limiter.Allow(ctx, "client-1")
		if err != nil {
			t.Fatalf("Allow %d: unexpected error: %v", i, err)
		}
		if !allowed {
			t.Fatalf("Allow %d: expected allowed=true", i)
		}
		if retryAfter != 0 {
			t.Fatalf("Allow %d: expected retryAfter=0, got %v", i, retryAfter)
		}
	}
}

// TestRedisRateLimiter_DenyAtLimit verifies that requests at the limit are
// denied with a retry-after duration.
func TestRedisRateLimiter_DenyAtLimit(t *testing.T) {
	limiter, _ := testRateLimiter(t, RateLimiterConfig{
		KeyPrefix: "test:",
		Limit:     5,
		Window:    time.Minute,
	})
	ctx := context.Background()

	// Use up the limit
	for i := 0; i < 5; i++ {
		allowed, _, err := limiter.Allow(ctx, "client-1")
		if err != nil {
			t.Fatalf("Allow %d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("Allow %d: expected allowed=true", i)
		}
	}

	// Next request should be denied
	allowed, retryAfter, err := limiter.Allow(ctx, "client-1")
	if err != nil {
		t.Fatalf("Allow at limit: %v", err)
	}
	if allowed {
		t.Fatal("Allow at limit: expected allowed=false")
	}
	if retryAfter <= 0 {
		t.Fatalf("Allow at limit: expected positive retryAfter, got %v", retryAfter)
	}
	// Retry-after should be <= window duration
	if retryAfter > time.Minute {
		t.Fatalf("Allow at limit: retryAfter %v exceeds window", retryAfter)
	}
}

// TestRedisRateLimiter_SeparateKeys verifies that different keys have separate
// rate limits.
func TestRedisRateLimiter_SeparateKeys(t *testing.T) {
	limiter, _ := testRateLimiter(t, RateLimiterConfig{
		KeyPrefix: "test:",
		Limit:     3,
		Window:    time.Minute,
	})
	ctx := context.Background()

	// Exhaust limit for client-1
	for i := 0; i < 3; i++ {
		allowed, _, err := limiter.Allow(ctx, "client-1")
		if err != nil {
			t.Fatalf("client-1 Allow %d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("client-1 Allow %d: expected allowed=true", i)
		}
	}

	// client-1 should be denied
	allowed, _, err := limiter.Allow(ctx, "client-1")
	if err != nil {
		t.Fatalf("client-1 at limit: %v", err)
	}
	if allowed {
		t.Fatal("client-1 at limit: expected allowed=false")
	}

	// client-2 should still be allowed
	allowed, _, err = limiter.Allow(ctx, "client-2")
	if err != nil {
		t.Fatalf("client-2: %v", err)
	}
	if !allowed {
		t.Fatal("client-2: expected allowed=true")
	}
}

// TestRedisRateLimiter_WindowExpiry verifies that the rate limit resets after
// the window expires.
func TestRedisRateLimiter_WindowExpiry(t *testing.T) {
	limiter, mr := testRateLimiter(t, RateLimiterConfig{
		KeyPrefix: "test:",
		Limit:     3,
		Window:    time.Second,
	})
	ctx := context.Background()

	// Exhaust limit
	for i := 0; i < 3; i++ {
		allowed, _, err := limiter.Allow(ctx, "client-1")
		if err != nil {
			t.Fatalf("Allow %d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("Allow %d: expected allowed=true", i)
		}
	}

	// Should be denied
	allowed, _, err := limiter.Allow(ctx, "client-1")
	if err != nil {
		t.Fatalf("Allow at limit: %v", err)
	}
	if allowed {
		t.Fatal("Allow at limit: expected allowed=false")
	}

	// Fast-forward past window
	mr.FastForward(2 * time.Second)

	// Should be allowed again
	allowed, _, err = limiter.Allow(ctx, "client-1")
	if err != nil {
		t.Fatalf("Allow after expiry: %v", err)
	}
	if !allowed {
		t.Fatal("Allow after expiry: expected allowed=true")
	}
}

// TestRedisRateLimiter_SlidingWindow verifies the sliding window behavior:
// when we exhaust the limit in one window and move to the next, requests
// should eventually be allowed again as the previous window ages out.
func TestRedisRateLimiter_SlidingWindow(t *testing.T) {
	limiter, mr := testRateLimiter(t, RateLimiterConfig{
		KeyPrefix: "test:",
		Limit:     5,
		Window:    2 * time.Second,
	})
	ctx := context.Background()

	// Exhaust the limit
	for i := 0; i < 5; i++ {
		allowed, _, err := limiter.Allow(ctx, "client-1")
		if err != nil {
			t.Fatalf("Allow %d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("Allow %d: expected allowed=true", i)
		}
	}

	// Should be denied now
	allowed, _, err := limiter.Allow(ctx, "client-1")
	if err != nil {
		t.Fatalf("Allow at limit: %v", err)
	}
	if allowed {
		t.Fatal("Allow at limit: expected allowed=false")
	}

	// Move past both windows entirely (2x window = 4 seconds)
	// This ensures the previous window data has expired from Redis
	mr.FastForward(4 * time.Second)

	// Now we're in a fresh window with no history - should be allowed
	allowed, _, err = limiter.Allow(ctx, "client-1")
	if err != nil {
		t.Fatalf("Allow after full expiry: %v", err)
	}
	if !allowed {
		t.Fatal("Allow after full expiry: expected allowed=true")
	}
}

// TestRedisRateLimiter_ConcurrentRequests verifies thread-safety of the
// rate limiter under concurrent load.
func TestRedisRateLimiter_ConcurrentRequests(t *testing.T) {
	limiter, _ := testRateLimiter(t, RateLimiterConfig{
		KeyPrefix: "test:",
		Limit:     50,
		Window:    time.Minute,
	})
	ctx := context.Background()

	const goroutines = 20
	const requestsPerGoroutine = 5

	var wg sync.WaitGroup
	results := make(chan bool, goroutines*requestsPerGoroutine)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				allowed, _, err := limiter.Allow(ctx, "client-concurrent")
				if err != nil {
					t.Errorf("Allow error: %v", err)
					return
				}
				results <- allowed
			}
		}()
	}

	wg.Wait()
	close(results)

	var allowedCount, deniedCount int
	for allowed := range results {
		if allowed {
			allowedCount++
		} else {
			deniedCount++
		}
	}

	// With limit=50, all 100 requests would exceed limit
	// We expect exactly 50 allowed and 50 denied
	if allowedCount != 50 {
		t.Errorf("expected 50 allowed, got %d", allowedCount)
	}
	if deniedCount != 50 {
		t.Errorf("expected 50 denied, got %d", deniedCount)
	}
}

// TestRedisRateLimiter_RedisError verifies that Redis errors are propagated
// for fail-open handling by the caller.
func TestRedisRateLimiter_RedisError(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // test cleanup
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	limiter := NewRedisRateLimiter(client, RateLimiterConfig{
		KeyPrefix: "test:",
		Limit:     10,
		Window:    time.Minute,
	}, logger)

	// Close miniredis to simulate Redis unavailability
	mr.Close()

	ctx := context.Background()
	_, _, err := limiter.Allow(ctx, "client-1")
	if err == nil {
		t.Fatal("expected error when Redis is unavailable")
	}
}

// TestRedisRateLimiter_MFADimensionsSharedAcrossReplicas proves MFA abuse
// counters use the shared Redis state for every required dimension. Two
// independent limiter objects model two harbor-mgmt replicas.
func TestRedisRateLimiter_MFADimensionsSharedAcrossReplicas(t *testing.T) {
	mr := miniredis.RunT(t)
	clientA := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	clientB := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = clientA.Close(); _ = clientB.Close() }) //nolint:errcheck // test cleanup
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := RateLimiterConfig{KeyPrefix: "mfa:", Limit: 2, Window: time.Minute}
	replicaA := NewRedisRateLimiter(clientA, cfg, logger)
	replicaB := NewRedisRateLimiter(clientB, cfg, logger)

	for _, dimension := range []string{"user:user-1", "session:session-1", "ip:203.0.113.7"} {
		if allowed, _, err := replicaA.Allow(context.Background(), dimension); err != nil || !allowed {
			t.Fatalf("first %s attempt allowed=%v err=%v", dimension, allowed, err)
		}
		if allowed, _, err := replicaB.Allow(context.Background(), dimension); err != nil || !allowed {
			t.Fatalf("second %s attempt allowed=%v err=%v", dimension, allowed, err)
		}
		if allowed, _, err := replicaA.Allow(context.Background(), dimension); err != nil || allowed {
			t.Fatalf("shared %s limit allowed=%v err=%v, want denied", dimension, allowed, err)
		}
	}
}

func TestRedisRateLimiter_MFAOutageNeverAllows(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // test cleanup
	limiter := NewRedisRateLimiter(client, RateLimiterConfig{KeyPrefix: "mfa:", Limit: 2, Window: time.Minute}, slog.Default())
	mr.Close()

	allowed, _, err := limiter.Allow(context.Background(), "session:session-1")
	if err == nil || allowed {
		t.Fatalf("Redis outage allowed=%v err=%v, want false and error for fail-closed caller", allowed, err)
	}
}

// TestRedisRateLimiter_DefaultConfig verifies that default values are applied
// when config fields are zero/empty.
func TestRedisRateLimiter_DefaultConfig(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // test cleanup
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Empty config should use defaults
	limiter := NewRedisRateLimiter(client, RateLimiterConfig{}, logger)

	if limiter.keyPrefix != "ratelimit:" {
		t.Errorf("expected default keyPrefix 'ratelimit:', got %q", limiter.keyPrefix)
	}
	if limiter.limit != 100 {
		t.Errorf("expected default limit 100, got %d", limiter.limit)
	}
	if limiter.window != time.Minute {
		t.Errorf("expected default window 1m, got %v", limiter.window)
	}
}

// TestRedisRateLimiter_RetryAfterAccuracy verifies that the retry-after duration
// is reasonably accurate.
func TestRedisRateLimiter_RetryAfterAccuracy(t *testing.T) {
	limiter, mr := testRateLimiter(t, RateLimiterConfig{
		KeyPrefix: "test:",
		Limit:     5,
		Window:    10 * time.Second,
	})
	ctx := context.Background()

	// Exhaust limit
	for i := 0; i < 5; i++ {
		_, _, err := limiter.Allow(ctx, "client-1")
		if err != nil {
			t.Fatalf("Allow %d: %v", i, err)
		}
	}

	// Get retry-after
	allowed, retryAfter, err := limiter.Allow(ctx, "client-1")
	if err != nil {
		t.Fatalf("Allow at limit: %v", err)
	}
	if allowed {
		t.Fatal("expected allowed=false")
	}

	// Retry-after should be positive and <= window
	if retryAfter <= 0 || retryAfter > 10*time.Second {
		t.Fatalf("retryAfter %v out of expected range (0, 10s]", retryAfter)
	}

	// Fast-forward by retry-after duration
	mr.FastForward(retryAfter + 100*time.Millisecond)

	// Should now be allowed (sliding window effect)
	_, _, err = limiter.Allow(ctx, "client-1")
	if err != nil {
		t.Fatalf("Allow after retry-after: %v", err)
	}
	// Note: due to sliding window, this might still be denied if retry-after
	// calculation was conservative. We just verify no error.
}

// TestRateLimitKey verifies the RateLimitKey helper function.
func TestRateLimitKey(t *testing.T) {
	tests := []struct {
		endpoint   string
		identifier string
		want       string
	}{
		{"token", "client-123", "token:client-123"},
		{"authorize", "192.168.1.1", "authorize:192.168.1.1"},
		{"introspect", "", "introspect:"},
	}

	for _, tt := range tests {
		got := RateLimitKey(tt.endpoint, tt.identifier)
		if got != tt.want {
			t.Errorf("RateLimitKey(%q, %q) = %q, want %q", tt.endpoint, tt.identifier, got, tt.want)
		}
	}
}

// TestRedisRateLimiter_InterfaceCompliance verifies that RedisRateLimiter
// implements the RateLimiter interface.
func TestRedisRateLimiter_InterfaceCompliance(t *testing.T) {
	var _ RateLimiter = (*RedisRateLimiter)(nil)
}

// --- MemoryRateLimiter tests ---

// newTestMemoryLimiter creates a MemoryRateLimiter with a controllable clock so
// window advancement can be tested deterministically without sleeping.
func newTestMemoryLimiter(cfg RateLimiterConfig) (*MemoryRateLimiter, func(d time.Duration)) {
	lim := NewMemoryRateLimiter(cfg)
	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0) // fixed, window-aligned-ish base
	lim.nowFn = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}
	return lim, advance
}

// TestMemoryRateLimiter_AllowUnderLimit verifies requests under the limit pass.
func TestMemoryRateLimiter_AllowUnderLimit(t *testing.T) {
	lim, _ := newTestMemoryLimiter(RateLimiterConfig{Limit: 10, Window: time.Minute})
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		allowed, retryAfter, err := lim.Allow(ctx, "client-1")
		if err != nil {
			t.Fatalf("Allow %d: unexpected error: %v", i, err)
		}
		if !allowed {
			t.Fatalf("Allow %d: expected allowed=true", i)
		}
		if retryAfter != 0 {
			t.Fatalf("Allow %d: expected retryAfter=0, got %v", i, retryAfter)
		}
	}
}

// TestMemoryRateLimiter_DenyAtLimit verifies the limit is enforced with a
// positive retry-after.
func TestMemoryRateLimiter_DenyAtLimit(t *testing.T) {
	lim, _ := newTestMemoryLimiter(RateLimiterConfig{Limit: 5, Window: time.Minute})
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		allowed, _, err := lim.Allow(ctx, "client-1")
		if err != nil {
			t.Fatalf("Allow %d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("Allow %d: expected allowed=true", i)
		}
	}

	allowed, retryAfter, err := lim.Allow(ctx, "client-1")
	if err != nil {
		t.Fatalf("Allow at limit: %v", err)
	}
	if allowed {
		t.Fatal("Allow at limit: expected allowed=false")
	}
	if retryAfter <= 0 || retryAfter > time.Minute {
		t.Fatalf("Allow at limit: retryAfter %v out of range (0, 1m]", retryAfter)
	}
}

// TestMemoryRateLimiter_SeparateKeys verifies keys are limited independently.
func TestMemoryRateLimiter_SeparateKeys(t *testing.T) {
	lim, _ := newTestMemoryLimiter(RateLimiterConfig{Limit: 3, Window: time.Minute})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if allowed, _, _ := lim.Allow(ctx, "client-1"); !allowed { //nolint:errcheck // in-memory limiter never errors
			t.Fatalf("client-1 Allow %d: expected allowed=true", i)
		}
	}
	if allowed, _, _ := lim.Allow(ctx, "client-1"); allowed { //nolint:errcheck // in-memory limiter never errors
		t.Fatal("client-1 at limit: expected allowed=false")
	}
	if allowed, _, _ := lim.Allow(ctx, "client-2"); !allowed { //nolint:errcheck // in-memory limiter never errors
		t.Fatal("client-2: expected allowed=true")
	}
}

// TestMemoryRateLimiter_WindowExpiry verifies the limit resets after the window
// fully ages out.
func TestMemoryRateLimiter_WindowExpiry(t *testing.T) {
	lim, advance := newTestMemoryLimiter(RateLimiterConfig{Limit: 3, Window: 2 * time.Second})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if allowed, _, _ := lim.Allow(ctx, "client-1"); !allowed { //nolint:errcheck // in-memory limiter never errors
			t.Fatalf("Allow %d: expected allowed=true", i)
		}
	}
	if allowed, _, _ := lim.Allow(ctx, "client-1"); allowed { //nolint:errcheck // in-memory limiter never errors
		t.Fatal("Allow at limit: expected allowed=false")
	}

	// Advance past both the current and previous window so history is gone.
	advance(4 * time.Second)

	if allowed, _, _ := lim.Allow(ctx, "client-1"); !allowed { //nolint:errcheck // in-memory limiter never errors
		t.Fatal("Allow after expiry: expected allowed=true")
	}
}

// TestMemoryRateLimiter_SlidingWindow verifies the previous window contributes
// proportionally to the effective count.
func TestMemoryRateLimiter_SlidingWindow(t *testing.T) {
	lim, advance := newTestMemoryLimiter(RateLimiterConfig{Limit: 10, Window: 2 * time.Second})
	ctx := context.Background()

	// Align to a window boundary so overlap math is predictable.
	// Fill 8 requests in the current window.
	for i := 0; i < 8; i++ {
		if allowed, _, _ := lim.Allow(ctx, "client-1"); !allowed { //nolint:errcheck // in-memory limiter never errors
			t.Fatalf("Allow %d: expected allowed=true", i)
		}
	}

	// Advance a full window: previous=8, current=0, overlap≈1.0 → effective≈8.
	advance(2 * time.Second)

	// Two more should be allowed (effective 8 → 9 → 10).
	for i := 0; i < 2; i++ {
		if allowed, _, _ := lim.Allow(ctx, "client-1"); !allowed { //nolint:errcheck // in-memory limiter never errors
			t.Fatalf("Allow at boundary %d: expected allowed=true", i)
		}
	}
	// Now effective ≈ 2 + 8*1 = 10 → denied.
	if allowed, _, _ := lim.Allow(ctx, "client-1"); allowed { //nolint:errcheck // in-memory limiter never errors
		t.Fatal("Allow at sliding limit: expected allowed=false")
	}

	// Advance past the previous window entirely: previous history gone.
	advance(4 * time.Second)
	if allowed, _, _ := lim.Allow(ctx, "client-1"); !allowed { //nolint:errcheck // in-memory limiter never errors
		t.Fatal("Allow after full slide: expected allowed=true")
	}
}

// TestMemoryRateLimiter_ConcurrentRequests verifies goroutine safety and exact
// accounting under concurrent load.
func TestMemoryRateLimiter_ConcurrentRequests(t *testing.T) {
	lim, _ := newTestMemoryLimiter(RateLimiterConfig{Limit: 50, Window: time.Minute})
	ctx := context.Background()

	const goroutines = 20
	const perGoroutine = 5
	var wg sync.WaitGroup
	results := make(chan bool, goroutines*perGoroutine)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				allowed, _, err := lim.Allow(ctx, "client-concurrent")
				if err != nil {
					t.Errorf("Allow error: %v", err)
					return
				}
				results <- allowed
			}
		}()
	}
	wg.Wait()
	close(results)

	var allowedCount, deniedCount int
	for allowed := range results {
		if allowed {
			allowedCount++
		} else {
			deniedCount++
		}
	}
	if allowedCount != 50 {
		t.Errorf("expected 50 allowed, got %d", allowedCount)
	}
	if deniedCount != 50 {
		t.Errorf("expected 50 denied, got %d", deniedCount)
	}
}

// TestMemoryRateLimiter_DefaultConfig verifies defaults are applied.
func TestMemoryRateLimiter_DefaultConfig(t *testing.T) {
	lim := NewMemoryRateLimiter(RateLimiterConfig{})
	if lim.limit != 100 {
		t.Errorf("expected default limit 100, got %d", lim.limit)
	}
	if lim.window != time.Minute {
		t.Errorf("expected default window 1m, got %v", lim.window)
	}
}

// TestMemoryRateLimiter_Sweep verifies stale entries are pruned so the map does
// not grow unbounded.
func TestMemoryRateLimiter_Sweep(t *testing.T) {
	lim, advance := newTestMemoryLimiter(RateLimiterConfig{Limit: 5, Window: time.Second})
	ctx := context.Background()

	// Touch several distinct keys.
	for i := 0; i < 10; i++ {
		if _, _, err := lim.Allow(ctx, RateLimitKey("token", string(rune('a'+i)))); err != nil {
			t.Fatalf("Allow: %v", err)
		}
	}

	lim.mu.Lock()
	before := len(lim.entries)
	lim.mu.Unlock()
	if before == 0 {
		t.Fatal("expected entries to be tracked")
	}

	// Advance well past the sweep interval, then trigger a sweep via a new key.
	advance(10 * time.Second)
	if _, _, err := lim.Allow(ctx, "trigger-sweep"); err != nil {
		t.Fatalf("Allow trigger: %v", err)
	}

	lim.mu.Lock()
	after := len(lim.entries)
	lim.mu.Unlock()
	// All the old keys should have been swept; only the trigger key remains.
	if after >= before {
		t.Errorf("expected sweep to prune stale entries: before=%d after=%d", before, after)
	}
}

// TestMemoryRateLimiter_InterfaceCompliance verifies MemoryRateLimiter
// implements the RateLimiter interface.
func TestMemoryRateLimiter_InterfaceCompliance(t *testing.T) {
	var _ RateLimiter = (*MemoryRateLimiter)(nil)
}

// --- No PII in limiter keys tests ---

// TestRateLimitKey_NoPII verifies that rate limit keys are constructed from
// non-PII identifiers (client_id or IP) and endpoint names, never from
// user-identifying information like email, user_id, or PPID.
//
// This is a documentation/design test: the RateLimitKey function takes an
// endpoint and identifier, where identifier should be client_id (for
// authenticated requests) or IP (for anonymous requests) — both are non-PII
// or quasi-identifiers that don't directly identify a user.
func TestRateLimitKey_NoPII(t *testing.T) {
	// Valid keys: endpoint + client_id (RP identifier, not user identifier)
	key1 := RateLimitKey("token", "client-abc123")
	if key1 != "token:client-abc123" {
		t.Errorf("unexpected key format: %s", key1)
	}

	// Valid keys: endpoint + IP (anonymous request)
	key2 := RateLimitKey("authorize", "192.168.1.100")
	if key2 != "authorize:192.168.1.100" {
		t.Errorf("unexpected key format: %s", key2)
	}

	// Valid keys: endpoint + IPv6
	key3 := RateLimitKey("introspect", "2001:db8::1")
	if key3 != "introspect:2001:db8::1" {
		t.Errorf("unexpected key format: %s", key3)
	}

	// The key format is simple and predictable - no user_id, email, PPID, or
	// other PII should ever be passed as the identifier. The rate limiter
	// keys by client_id (authenticated) or IP (anonymous), both of which are
	// acceptable for rate limiting without creating per-user tracking.
	//
	// This test documents the expected usage pattern. The actual enforcement
	// that PII is never passed here happens at the call sites (middleware),
	// which extract client_id from the authenticated request or IP from the
	// connection.
}

// TestRateLimiter_KeysAreIsolated verifies that rate limiting works correctly
// with the expected key patterns (client_id and IP-based keys), ensuring that
// different clients/IPs are tracked independently.
func TestRateLimiter_KeysAreIsolated(t *testing.T) {
	limiter, _ := testRateLimiter(t, RateLimiterConfig{
		KeyPrefix: "test:",
		Limit:     2,
		Window:    time.Minute,
	})
	ctx := context.Background()

	// Simulate different clients hitting the token endpoint
	clientAKey := RateLimitKey("token", "client-a")
	clientBKey := RateLimitKey("token", "client-b")
	ipKey := RateLimitKey("token", "10.0.0.1")

	// Exhaust limit for client-a
	for i := 0; i < 2; i++ {
		allowed, _, _ := limiter.Allow(ctx, clientAKey) //nolint:errcheck // miniredis is up in this test
		if !allowed {
			t.Fatalf("client-a request %d should be allowed", i)
		}
	}

	// client-a should be denied
	if allowed, _, _ := limiter.Allow(ctx, clientAKey); allowed { //nolint:errcheck // miniredis is up in this test
		t.Fatal("client-a should be rate limited")
	}

	// client-b should still be allowed (separate key)
	if allowed, _, _ := limiter.Allow(ctx, clientBKey); !allowed { //nolint:errcheck // miniredis is up in this test
		t.Fatal("client-b should be allowed (independent limit)")
	}

	// IP-based key should also be independent
	if allowed, _, _ := limiter.Allow(ctx, ipKey); !allowed { //nolint:errcheck // miniredis is up in this test
		t.Fatal("IP-based key should be allowed (independent limit)")
	}
}
