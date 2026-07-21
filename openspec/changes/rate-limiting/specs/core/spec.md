# Spec: Per-client hot-path rate limiting

Implements a Redis-backed `RateLimiter` and hot-path middleware that throttles
`/introspect`, `/token`, and `/authorize` per `client_id` (per-IP for anonymous
callers), returning `429 Too Many Requests` + `Retry-After` on over-limit and
failing **open** on Redis outage. Defines the limiter contract, keying and
response behaviour, and the availability posture.

## ADDED Requirements

### Requirement: REQ-001 RateLimiter contract

The system SHALL provide a Redis-backed RateLimiter with atomic
increment-and-check semantics.

The system MUST provide a `RedisRateLimiter` implementing a `RateLimiter`
interface with an `Allow` method that atomically increments a windowed counter
and reports whether the request is within the configured limit, plus the
`Retry-After` duration when it is not. The atomic operation MUST be a Lua script
so concurrent requests across replicas cannot both bypass the limit.

```go
package clients

type RateLimiter interface {
    Allow(ctx context.Context, key string, limit int, window time.Duration) (allowed bool, retryAfter time.Duration, err error)
}

type RedisRateLimiter struct{}

func NewRedisRateLimiter(client *redis.Client) *RedisRateLimiter
```

#### Scenario: Under-limit request is allowed

**Given** a key with fewer requests than the configured limit in the current window
**When** `Allow` is called
**Then** it returns `allowed = true` and a zero `retryAfter`

#### Scenario: RedisRateLimiter satisfies RateLimiter interface

**Given** a `RedisRateLimiter` instance
**When** assigned to a variable of type `RateLimiter`
**Then** the assignment compiles (compile-time interface assertion)

#### Scenario: Concurrent requests are counted atomically

**Given** multiple concurrent requests for the same key at the limit boundary
**When** they call `Allow` simultaneously
**Then** no more than the configured limit are allowed (Lua atomicity bound)

### Requirement: REQ-002 Per-client keying and 429 response

The system SHALL key limits per client_id with a per-IP fallback and return 429
with Retry-After on over-limit.

The hot-path middleware MUST derive the limiter key from the authenticated
`client_id` (Basic auth) when present, and fall back to the client IP for
anonymous / pre-auth requests. Per-client and per-IP buckets MUST be
independent. An over-limit request MUST receive `429 Too Many Requests` with a
`Retry-After` header (seconds until window reset, clamped to `[0, window]`) and
a `rate_limited` error body. The middleware MUST be applied to `/introspect`,
`/token`, and `/authorize`.

#### Scenario: Over-limit request is rejected with 429

**Given** a `client_id` that has reached its configured limit in the current window
**When** it sends another request to a rate-limited route
**Then** the response is `429 Too Many Requests` with a non-negative `Retry-After` header and a `rate_limited` error body

#### Scenario: Per-client and per-IP buckets are independent

**Given** an anonymous caller (per-IP) that has exhausted its budget
**When** an authenticated client (per-`client_id`) sends a request from the same IP
**Then** the authenticated request is evaluated against its own client bucket and is allowed if under its limit

#### Scenario: Window reset allows requests again

**Given** a key that was over-limit
**When** the configured window has elapsed
**Then** subsequent requests are allowed again

### Requirement: REQ-003 Fail-open on Redis outage

The system SHALL fail open when the rate-limiter backend is unavailable.

When the Redis backend returns an error or is unreachable, the middleware MUST
allow the request (fail-open), MUST log the condition loudly, and MUST emit a
metric. A rate-limiter outage MUST NOT reject hot-path traffic or break token
verification.

#### Scenario: Redis outage allows the request

**Given** a Redis backend that is unavailable
**When** a request reaches the rate-limiting middleware
**Then** the request is allowed to proceed, a warning is logged, and a `rate_limiter_unavailable` metric is emitted

#### Scenario: Verification is never blocked by limiter failure

**Given** the rate limiter cannot reach Redis
**When** a valid token-verification request arrives
**Then** it is served normally (the limiter never fails closed on the hot path)
