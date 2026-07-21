# Tasks: Per-client hot-path rate limiting (Redis-backed)

## Prerequisites

- [ ] **`token-introspection` must land first (hard dependency).** The limiter
  must protect `POST /introspect`, which does not exist until
  `token-introspection` is promoted, and it shares the `internal/oidcapi/`
  router/middleware surface that change extends. Build this only after
  `token-introspection` is on `main`.

## Implementation

- [ ] `internal/clients/ratelimit.go`: `RateLimiter` interface
  (`Allow(ctx, key, limit, window) (allowed bool, retryAfter time.Duration, err error)`) + `RedisRateLimiter` wrapping `*redis.Client`.
- [ ] Lua-atomic sliding-window (or token-bucket) increment-and-check so
  concurrent requests across replicas cannot both bypass the limit.
- [ ] In-memory `RateLimiter` fallback for when `REDIS_URL` is unset (dev).
- [ ] `internal/oidcapi/ratelimit.go`: hot-path middleware — extract `client_id`
  from Basic auth (per-client bucket) or fall back to per-IP (trusted forwarded
  header); look up the per-route limit; call `Allow`.
- [ ] Apply the middleware to `/introspect`, `/token`, and `/authorize` on the
  hot-path router.
- [ ] On over-limit: respond `429 Too Many Requests` with `Retry-After`
  (clamped `[0, window]`) and a `rate_limited` OAuth-style error body.
- [ ] Fail-open: on any Redis error, allow the request, log loudly, emit a
  `rate_limiter_unavailable` metric.
- [ ] Configurable per-route / per-identity limits via env with sane defaults.
- [ ] `cmd/harbor-hot/main.go`: wire the limiter middleware when `REDIS_URL` is
  set; no-op (allow-all) middleware when unset.
- [ ] Compile-time assertion: `var _ RateLimiter = (*RedisRateLimiter)(nil)`.

## Tests

- [ ] `internal/clients/ratelimit_test.go`: miniredis unit tests + real-Redis
  Lua-path tests (Docker Compose e2e) for atomicity.
- [ ] Under-limit requests pass; the N+1th request in a window returns `429`.
- [ ] `429` responses carry a correct, non-negative `Retry-After`.
- [ ] Per-client and per-IP buckets are independent (exhausting one does not
  affect the other).
- [ ] Window reset: after the window elapses, requests are allowed again.
- [ ] Redis outage fails **open**: request allowed, warning logged, metric
  emitted.
- [ ] Concurrent requests (multiple goroutines) never exceed the limit by more
  than the atomicity bound.
- [ ] No PII in limiter keys (only `client_id` / IP).

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate rate-limiting --strict`
