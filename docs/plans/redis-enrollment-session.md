---
title: Redis enrollment session — multi-replica enrollment→registration handoff
status: draft
design_refs: [§4.4, §9]
targets: [internal/mgmtapi/, cmd/harbor-mgmt/]
promoted_to: null
openspec: changes/redis-enrollment-session
created: 2026-07-22
---

# Redis enrollment session (plan)

> **Dependency order:** depends on the existing `EnrollmentSessionStore`
> interface and `InMemoryEnrollmentSessionStore` in `internal/mgmtapi/session.go`
> (both present). Parallels `bff-flow-wiring`; both consume the shared
> `redisClient`. Independent of `webauthn-db-wiring`. Can run in parallel with
> both other plans on Weft.

## Problem

The enrollment→passkey-registration handoff uses
`InMemoryEnrollmentSessionStore`, which lives in one process's memory. Under more
than one `harbor-mgmt` replica the `POST /enroll` that mints the session key and
the register/begin + register/finish that read it may land on different replicas,
so the second replica cannot resolve the user handle and enrollment fails. §4.4
calls for a shared, short-TTL store (Redis) so the handoff works across replicas;
the in-memory store's own doc comment already flags this as the production gap.

Two properties matter and must be preserved from the interface contract:

- The store is **NOT one-time-use**: both register/begin and register/finish read
  the same key within one enrollment, so `UserHandle` is a multi-read GET.
- The TTL is short (10 minutes) — enrollment and first-passkey registration are a
  single contiguous flow.

## Proposed approach

Add a Redis-backed `RedisEnrollmentSessionStore` implementing the existing
`EnrollmentSessionStore` interface, and wire it in `harbor-mgmt` when a Redis
client is available:

1. **`internal/mgmtapi/session_redis.go`** — `RedisEnrollmentSessionStore`:
   - Redis key format `enrollment_session:<key>`.
   - `Save(ctx, key, userHandle)` → `SET key value EX <ttl>` with **no NX flag**
     (multi-read allowed; the same key may be written/refreshed by the enroll handler).
   - `UserHandle(ctx, key)` → `GET` only, **no delete** (not one-time-use);
     `redis.Nil` maps to `ErrEnrollmentSessionNotFound`.
   - TTL = 10 minutes, matching `InMemoryEnrollmentSessionStore`.
   - `var _ EnrollmentSessionStore = (*RedisEnrollmentSessionStore)(nil)`.
2. **`internal/mgmtapi/session_redis_test.go`** — miniredis-backed tests:
   Save+UserHandle round-trip; missing key ⇒ `ErrEnrollmentSessionNotFound`;
   multiple `UserHandle` reads on one key all succeed (not one-time-use); TTL
   expiry (miniredis fast-forward) ⇒ `ErrEnrollmentSessionNotFound`.
3. **`internal/mgmtapi/server.go`** — ensure the
   `WithEnrollmentSessions(EnrollmentSessionStore) *Server` builder method
   exists so `main` can attach the chosen store.
4. **`cmd/harbor-mgmt/main.go`** — when `redisClient != nil`, build a
   `RedisEnrollmentSessionStore`; else keep `InMemoryEnrollmentSessionStore`
   (with a `Warn` log); call `.WithEnrollmentSessions(enrollmentStore)` on
   `mgmtServer`.

No new migrations.

## DESIGN alignment

Realizes §4.4 (shared, short-TTL store for cross-replica session handoff) for the
§9 enrollment→registration flow, closing the multi-replica gap the in-memory
store's comment already documents. Does **not** change `DESIGN.md`.

## Target code paths

- `internal/mgmtapi/session_redis.go` — new `RedisEnrollmentSessionStore`.
- `internal/mgmtapi/session_redis_test.go` — new miniredis tests.
- `internal/mgmtapi/server.go` — `WithEnrollmentSessions` builder (add if missing).
- `cmd/harbor-mgmt/main.go` — select + wire the enrollment session store.

## Implementation checklist

- [ ] `internal/mgmtapi/session_redis.go`: `RedisEnrollmentSessionStore` struct
      wrapping `*redis.Client` and a 10-minute TTL.
- [ ] `Save` → `SET key value EX <ttl>` (no NX); `UserHandle` → `GET` only (no
      delete); `redis.Nil` maps to `ErrEnrollmentSessionNotFound`.
- [ ] Compile-time check `var _ EnrollmentSessionStore = (*RedisEnrollmentSessionStore)(nil)`.
- [ ] `internal/mgmtapi/session_redis_test.go`: miniredis tests for round-trip,
      missing key, multi-read (not one-time-use), and TTL expiry
      (`mr.FastForward(11 * time.Minute)`).
- [ ] `internal/mgmtapi/server.go`: ensure `WithEnrollmentSessions(EnrollmentSessionStore) *Server` exists.
- [ ] `cmd/harbor-mgmt/main.go`: `var enrollmentStore mgmtapi.EnrollmentSessionStore`;
      when `redisClient != nil`, use `mgmtapi.NewRedisEnrollmentSessionStore(redisClient)`;
      else log `Warn` and use `mgmtapi.NewInMemoryEnrollmentSessionStore()`.
      Call `.WithEnrollmentSessions(enrollmentStore)` on `mgmtServer`.
- [ ] Author & verify paired OpenSpec change: `openspec validate redis-enrollment-session --strict`.
- [ ] Reconcile & promote: `@plan promote redis-enrollment-session`.

## Risks & open questions

- **One-time-use temptation:** it would be a bug to delete on `UserHandle` or add
  an NX flag — both would break the legitimate two-read (begin + finish) flow.
  The tests explicitly assert multi-read to guard against this.
- **TTL drift:** the Redis TTL must match the in-memory 10-minute TTL so behaviour
  is identical across the two stores; keep it as a single documented constant.
- No PII risk: only an opaque user handle is stored under an opaque key, for
  minutes.

## Definition of done

`go build/vet/test ./...` green; with `redisClient` set, `harbor-mgmt` resolves
the enrollment handoff across replicas via Redis; without it, the in-memory store
is used with a `Warn` log; multi-read and TTL-expiry behaviours are test-enforced;
`make agent-check` clean. Ready to `@plan promote`.
