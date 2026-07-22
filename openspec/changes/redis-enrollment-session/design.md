# Design: Redis enrollment session

## Key Decisions

### Decision 1: Implement the existing `EnrollmentSessionStore` interface
**Chosen:** A new `RedisEnrollmentSessionStore` behind the existing interface,
with a compile-time `var _ EnrollmentSessionStore = (*RedisEnrollmentSessionStore)(nil)`.
**Rationale:** The interface is the seam the enrollment handlers already depend
on; implementing it lets `main` swap stores with zero handler changes and keeps
the in-memory store as a drop-in equivalent.
**Alternatives considered:** A bespoke Redis type wired directly into the
handlers (couples HTTP to Redis, rejected).

### Decision 2: `Save` uses `SET EX` with NO `NX` flag — multi-read, not one-time-use
**Chosen:** Plain `SET key value EX <ttl>`; no `NX`.
**Rationale:** The contract states the store is NOT one-time-use — both
register/begin and register/finish read the same key within one enrollment. An
`NX` guard (as used by the WebAuthn ceremony session's `Save` path) would wrongly
reject a legitimate re-write/refresh of the handoff session. Omitting `NX` keeps
the semantics identical to `InMemoryEnrollmentSessionStore.Save`.
**Alternatives considered:** `SET NX` (breaks the two-read flow, rejected).

### Decision 3: `UserHandle` is a pure `GET` — never delete on read
**Chosen:** `GET` only; map `redis.Nil` to `ErrEnrollmentSessionNotFound`; do not
delete the key.
**Rationale:** Deleting on read would make the store one-time-use and break
register/finish after register/begin already consumed the key. Expiry is left to
the Redis TTL, exactly as the in-memory store treats an expired entry as absent.
**Alternatives considered:** Delete-on-read (one-time-use, wrong for this flow,
rejected).

### Decision 4: TTL fixed at 10 minutes to match the in-memory store
**Chosen:** A 10-minute TTL, matching `enrollmentSessionTTL` used by
`InMemoryEnrollmentSessionStore`.
**Rationale:** The two stores must be behaviourally interchangeable; a matching
short TTL bounds the handoff to the contiguous enrollment→registration flow (§4.4)
without leaving stale handles around.
**Alternatives considered:** A different/configurable TTL (risks divergence
between the two stores, rejected for v1).

### Decision 5: Select the store in `main` on `redisClient != nil`
**Chosen:** Build the Redis store when `redisClient != nil`, else the in-memory
store, then attach via `.WithEnrollmentSessions`.
**Rationale:** Mirrors the other Redis-vs-memory selections in the binary and
keeps a single, dev-friendly fallback path; the presence of the Redis client is
the natural signal.
**Alternatives considered:** A dedicated env toggle (redundant with the client's
presence, rejected).
