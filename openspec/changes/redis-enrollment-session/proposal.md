# Proposal: Redis enrollment session — multi-replica enrollment→registration handoff

## Problem

The enrollment→passkey-registration handoff uses `InMemoryEnrollmentSessionStore`,
which lives in one process's memory. With more than one `harbor-mgmt` replica,
the `POST /enroll` that mints the session key and the register/begin +
register/finish that read it can land on different replicas, so the handoff
fails. §4.4 calls for a shared, short-TTL store (Redis); the in-memory store's
own comment flags this as the production gap. The store is explicitly **not
one-time-use** (both begin and finish read the same key) and its TTL is short (10
minutes).

## Proposed Solution

Add a Redis-backed `RedisEnrollmentSessionStore` implementing the existing
`EnrollmentSessionStore` interface, and select it in `harbor-mgmt` when Redis is
available:

- New `internal/mgmtapi/session_redis.go`: key `enrollment_session:<key>`; `Save`
  → `SET key value EX <ttl>` (no NX — multi-read allowed); `UserHandle` → `GET`
  only (no delete); `redis.Nil` ⇒ `ErrEnrollmentSessionNotFound`; TTL 10 minutes
  matching the in-memory store;
  `var _ EnrollmentSessionStore = (*RedisEnrollmentSessionStore)(nil)`.
- New `internal/mgmtapi/session_redis_test.go`: miniredis tests for round-trip,
  missing key, multi-read (not one-time-use), and TTL expiry.
- `internal/mgmtapi/server.go`: ensure
  `WithEnrollmentSessions(EnrollmentSessionStore) *Server` builder exists.
- `cmd/harbor-mgmt/main.go`: use the Redis store when `redisClient != nil`
  (with an `Info` log), else `InMemoryEnrollmentSessionStore` (with a `Warn` log);
  call `.WithEnrollmentSessions(enrollmentStore)` on `mgmtServer`.

## Non-Goals

- No new migrations.
- No change to the `EnrollmentSessionStore` interface contract (still multi-read,
  not one-time-use).
- No change to the enrollment HTTP handlers themselves.

## Success Criteria

- [ ] `RedisEnrollmentSessionStore` implements `EnrollmentSessionStore` (compile-time check).
- [ ] Key is `enrollment_session:<key>`; `Save` uses `SET EX` (no NX);
      `UserHandle` uses `GET` only and never deletes.
- [ ] `UserHandle` on a missing/expired key returns `ErrEnrollmentSessionNotFound`.
- [ ] Multiple `UserHandle` reads on one key all succeed (not one-time-use).
- [ ] TTL is 10 minutes, matching `InMemoryEnrollmentSessionStore`.
- [ ] `harbor-mgmt` selects Redis when `redisClient != nil`, else in-memory, via
      `.WithEnrollmentSessions`.
- [ ] `go build ./... && go vet ./... && go test ./...` pass.
- [ ] `make agent-check` clean.
