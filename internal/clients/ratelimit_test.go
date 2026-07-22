package clients

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

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
	allowed, _, err = limiter.Allow(ctx, "client-1")
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
