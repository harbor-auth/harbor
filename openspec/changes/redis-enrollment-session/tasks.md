# Tasks: Redis enrollment session

## Prerequisites

- [ ] `EnrollmentSessionStore` interface + `InMemoryEnrollmentSessionStore`
      exist (`internal/mgmtapi/session.go`).
- [ ] `ErrEnrollmentSessionNotFound` and `enrollmentSessionTTL` (10m) exist in
      `internal/mgmtapi/session.go`.
- [ ] `redisClient` is available in `cmd/harbor-mgmt/main.go`; `miniredis` and
      `go-redis` are available for tests (both in `go.mod`).

## Implementation

- [ ] `internal/mgmtapi/session_redis.go`: `RedisEnrollmentSessionStore` struct
      wrapping `*redis.Client` and a 10-minute TTL constant.
- [ ] `Save` → `SET key value EX <ttl>` with NO `NX` flag (multi-read allowed).
- [ ] `UserHandle` → `GET` only (no delete); map `redis.Nil` to
      `ErrEnrollmentSessionNotFound`.
- [ ] Add `var _ EnrollmentSessionStore = (*RedisEnrollmentSessionStore)(nil)`.
- [ ] `NewRedisEnrollmentSessionStore(client *redis.Client) *RedisEnrollmentSessionStore`
      constructor using `enrollmentSessionTTL` (10 minutes) as the TTL.
- [ ] `internal/mgmtapi/server.go`: ensure
      `WithEnrollmentSessions(EnrollmentSessionStore) *Server` builder exists.
- [ ] `cmd/harbor-mgmt/main.go`: declare `var enrollmentStore mgmtapi.EnrollmentSessionStore`;
      when `redisClient != nil`, assign
      `mgmtapi.NewRedisEnrollmentSessionStore(redisClient)` and log `Info`;
      else assign `mgmtapi.NewInMemoryEnrollmentSessionStore()` and log `Warn`.
      Call `.WithEnrollmentSessions(enrollmentStore)` on `mgmtServer`.

## Tests

- [ ] `internal/mgmtapi/session_redis_test.go` (miniredis via `miniredis.RunT`):
- [ ] `Save` + `UserHandle` round-trip returns the stored user handle.
- [ ] `UserHandle` on a missing key returns `ErrEnrollmentSessionNotFound`.
- [ ] Multiple `UserHandle` calls on the same key all succeed (not one-time-use).
- [ ] TTL expiry (`mr.FastForward(11 * time.Minute)`) returns
      `ErrEnrollmentSessionNotFound`.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate redis-enrollment-session --strict`
