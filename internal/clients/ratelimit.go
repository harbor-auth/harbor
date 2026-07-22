package clients

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter defines the interface for rate limiting requests. Implementations
// are keyed by client_id (authenticated) or IP (anonymous) and return whether
// a request is allowed, plus a retry-after duration when denied.
//
// The interface is designed for hot-path endpoints (/introspect, /token,
// /authorize) where abuse and enumeration defense is critical.
type RateLimiter interface {
	// Allow checks if a request identified by key is allowed under the rate
	// limit. Returns:
	//   - allowed: true if the request should proceed, false if rate-limited
	//   - retryAfter: when denied, how long until the client should retry;
	//     zero when allowed
	//   - err: non-nil on infrastructure errors (Redis unavailable, etc.)
	//
	// Callers MUST implement fail-open semantics: if err != nil, allow the
	// request (log loudly, emit metrics) rather than blocking legitimate
	// traffic during Redis outages.
	Allow(ctx context.Context, key string) (allowed bool, retryAfter time.Duration, err error)
}

// Compile-time interface assertion.
var _ RateLimiter = (*RedisRateLimiter)(nil)

// RedisRateLimiter implements RateLimiter using a Redis-backed sliding window
// counter with Lua-atomic operations. The sliding window algorithm provides
// smoother rate limiting than fixed windows by considering requests from the
// previous window proportionally.
//
// Algorithm: sliding window log with counter approximation
//   - Each window is stored as a Redis key with TTL = 2 * window duration
//   - Current window count + (previous window count * overlap ratio) = effective count
//   - If effective count >= limit, request is denied with Retry-After
//
// Fail-open posture: Redis unavailability returns an error; the caller (middleware)
// is responsible for allowing the request and logging/emitting metrics.
type RedisRateLimiter struct {
	client    *redis.Client
	keyPrefix string
	limit     int           // max requests per window
	window    time.Duration // sliding window duration (minimum 1 second)
	logger    *slog.Logger
}

// RateLimiterConfig holds configuration for creating a RedisRateLimiter.
type RateLimiterConfig struct {
	// KeyPrefix is prepended to all Redis keys (e.g., "ratelimit:token:").
	KeyPrefix string
	// Limit is the maximum number of requests allowed per window.
	Limit int
	// Window is the sliding window duration.
	Window time.Duration
}

// NewRedisRateLimiter creates a Redis-backed rate limiter with sliding window.
// The logger is used for diagnostic messages on Redis errors.
func NewRedisRateLimiter(client *redis.Client, cfg RateLimiterConfig, logger *slog.Logger) *RedisRateLimiter {
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "ratelimit:"
	}
	if cfg.Limit <= 0 {
		cfg.Limit = 100 // sensible default
	}
	if cfg.Window < time.Second {
		cfg.Window = time.Minute // minimum 1 second, default 1 minute
	}
	return &RedisRateLimiter{
		client:    client,
		keyPrefix: cfg.KeyPrefix,
		limit:     cfg.Limit,
		window:    cfg.Window,
		logger:    logger,
	}
}

// slidingWindowScript is a Lua script for atomic sliding window rate limiting.
// It implements a sliding window log approximation that is both accurate and
// memory-efficient (only two counters per key, not a full request log).
//
// Algorithm:
//  1. Get current and previous window counters
//  2. Calculate the overlap ratio (how much of the previous window is still relevant)
//  3. Compute effective count = current + (previous * overlap)
//  4. If under limit, increment current counter and allow
//  5. If at/over limit, deny and return retry-after seconds
//
// KEYS[1] = current window key
// KEYS[2] = previous window key
// ARGV[1] = limit (max requests per window)
// ARGV[2] = window duration in seconds
// ARGV[3] = current timestamp in milliseconds
//
// Returns: {allowed (0/1), retry_after_ms, current_count, effective_count}
var slidingWindowScript = redis.NewScript(`
local current_key = KEYS[1]
local previous_key = KEYS[2]
local limit = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2]) * 1000
local now_ms = tonumber(ARGV[3])

-- Calculate window boundaries
local current_window_start = math.floor(now_ms / window_ms) * window_ms
local previous_window_start = current_window_start - window_ms

-- Get counts from both windows
local current_count = tonumber(redis.call('GET', current_key) or '0')
local previous_count = tonumber(redis.call('GET', previous_key) or '0')

-- Calculate overlap ratio: how much of the previous window is still within our sliding window
-- At the start of current window, overlap = 1.0; at the end, overlap = 0.0
local elapsed_in_current = now_ms - current_window_start
local overlap_ratio = 1.0 - (elapsed_in_current / window_ms)
if overlap_ratio < 0 then overlap_ratio = 0 end

-- Effective count using sliding window approximation
local effective_count = current_count + (previous_count * overlap_ratio)

if effective_count >= limit then
    -- Rate limited: calculate retry-after (time until window slides enough)
    -- We need effective_count to drop below limit
    -- effective_count = current + previous * overlap
    -- As time passes, overlap decreases, so effective_count decreases
    -- We want: current + previous * new_overlap < limit
    -- new_overlap = 1 - (elapsed + wait) / window
    -- Solving for wait when previous > 0:
    --   current + previous * (1 - (elapsed + wait) / window) < limit
    --   previous * (1 - (elapsed + wait) / window) < limit - current
    --   1 - (elapsed + wait) / window < (limit - current) / previous
    --   (elapsed + wait) / window > 1 - (limit - current) / previous
    --   elapsed + wait > window * (1 - (limit - current) / previous)
    --   wait > window * (1 - (limit - current) / previous) - elapsed
    
    local retry_after_ms
    if previous_count > 0 and current_count < limit then
        local target_overlap = (limit - current_count - 0.001) / previous_count
        if target_overlap < 0 then target_overlap = 0 end
        local target_elapsed = window_ms * (1 - target_overlap)
        retry_after_ms = math.ceil(target_elapsed - elapsed_in_current)
        if retry_after_ms < 1 then retry_after_ms = 1 end
    else
        -- Current window alone exceeds limit; must wait for new window
        retry_after_ms = math.ceil(window_ms - elapsed_in_current)
        if retry_after_ms < 1 then retry_after_ms = 1 end
    end
    
    return {0, retry_after_ms, current_count, math.floor(effective_count)}
end

-- Under limit: increment current window counter and allow
local new_count = redis.call('INCR', current_key)

-- Set TTL to 2x window so previous window data is available for overlap calculation
local ttl_seconds = math.ceil(window_ms / 1000 * 2)
redis.call('EXPIRE', current_key, ttl_seconds)

return {1, 0, new_count, math.floor(effective_count) + 1}
`)

// Allow implements RateLimiter using a sliding window algorithm.
func (r *RedisRateLimiter) Allow(ctx context.Context, key string) (bool, time.Duration, error) {
	now := time.Now()
	nowMs := now.UnixMilli()
	windowSecs := int64(r.window.Seconds())

	// Calculate window keys based on timestamp
	currentWindowStart := (nowMs / (windowSecs * 1000)) * (windowSecs * 1000)
	previousWindowStart := currentWindowStart - (windowSecs * 1000)

	currentKey := fmt.Sprintf("%s%s:%d", r.keyPrefix, key, currentWindowStart)
	previousKey := fmt.Sprintf("%s%s:%d", r.keyPrefix, key, previousWindowStart)

	result, err := slidingWindowScript.Run(ctx, r.client,
		[]string{currentKey, previousKey},
		r.limit,
		windowSecs,
		nowMs,
	).Slice()
	if err != nil {
		// Log and return error for fail-open handling by caller
		r.logger.Error("rate limiter redis error", "key", key, "error", err)
		return false, 0, fmt.Errorf("ratelimit: redis script: %w", err)
	}

	if len(result) < 2 {
		return false, 0, fmt.Errorf("ratelimit: unexpected script result length: %d", len(result))
	}

	allowed := result[0].(int64) == 1
	retryAfterMs := result[1].(int64)

	if !allowed {
		return false, time.Duration(retryAfterMs) * time.Millisecond, nil
	}

	return true, 0, nil
}

// RateLimitKey generates a rate limit key for the given endpoint and identifier.
// Use this helper to build consistent keys across the codebase.
//
// For authenticated requests, use client_id as the identifier.
// For anonymous requests, use the client IP.
func RateLimitKey(endpoint, identifier string) string {
	return fmt.Sprintf("%s:%s", endpoint, identifier)
}
