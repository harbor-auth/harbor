# Tasks: Authorization Code Persistence (Redis-backed)

## Prerequisites

- None (DAG layer 0 — no dependencies on other features)

## Implementation

- [ ] Add `github.com/redis/go-redis/v9` dependency to `go.mod`; run `go mod tidy`.
- [ ] Add `github.com/alicebob/miniredis/v2` as a test dependency for hermetic Redis tests.
- [ ] Create `internal/clients/redis.go`: `ConnectRedis(ctx, logger) (*redis.Client, error)` — reads `REDIS_URL`, returns `(nil, nil)` when unset.
- [ ] Create `internal/clients/codes.go`: `RedisAuthCodeStore` implementing `oidc.AuthCodeStore` with `Save`, `Peek`, `Consume`.
- [ ] Implement `Save`: JSON marshal + `SET NX EX` with TTL from `code.ExpiresAt`.
- [ ] Implement `Peek`: pipeline `GET` code + `EXISTS` consumed marker; return `(AuthCode, found, consumed, error)`.
- [ ] Implement `Consume`: Lua script for atomic check-and-mark; consumed marker TTL = 2× code TTL.
- [ ] Create `internal/clients/codes_test.go`: miniredis-based tests for save→peek→consume, double-consume, expiry, concurrent consume.
- [ ] Wire `RedisAuthCodeStore` in `cmd/harbor-hot/main.go` when `REDIS_URL` is set; keep `InMemoryAuthCodeStore` fallback with warning.
- [ ] Remove or update the existing SCAFFOLD comment in `main.go` once real wiring is in place.

## Tests

- [ ] `TestRedisCodeStore_SavePeekConsume` — round-trip validation.
- [ ] `TestRedisCodeStore_DoubleConsume` — reuse detection returns `ConsumeReused`.
- [ ] `TestRedisCodeStore_Expiry` — expired code returns `ConsumeNotFound`.
- [ ] `TestRedisCodeStore_ConsumedMarkerOutlivesCode` — 2× TTL behavior.
- [ ] `TestRedisCodeStore_ConcurrentConsume` — Lua atomicity (10 goroutines, 1 wins).
- [ ] `TestRedisCodeStore_SaveDuplicate` — duplicate code returns error.
- [ ] `TestConnectRedis_NoURL` — returns `(nil, nil)` when `REDIS_URL` unset.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `npx @fission-ai/openspec@latest "/opsx:verify auth-code-persistence-dd2e7f20"`
