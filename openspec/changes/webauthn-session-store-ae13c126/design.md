# Design: WebAuthn session persistence (Redis-backed)

## Key Decisions

### Decision 1: Redis with SET NX EX for Save
**Chosen:** `SET NX EX <ttl>` for storing ceremony sessions.
**Rationale:** The `NX` flag prevents a second Begin call for the same key from
overwriting an in-flight challenge (race-safe). The `EX` flag handles TTL-based
expiry with no cleanup job. Redis is operationally simpler than Postgres for
5-minute ephemeral data.
**Alternatives considered:** Postgres with a GC job (adds complexity, rejected);
plain `SET EX` without `NX` (allows race overwrites, rejected).

### Decision 2: Lua script for atomic Take (GET+DEL)
**Chosen:** A Lua script that atomically `GET`s the key, `DEL`s the key, and
returns the value.
**Rationale:** Lua scripts execute atomically in Redis. Two concurrent `Take`
calls cannot both succeed — the first wins, the second receives
`ErrSessionNotFound`. This matches the single-use semantics required by WebAuthn
(a challenge cannot be replayed).
**Alternatives considered:** `GETDEL` command (requires Redis 6.2+; Lua is more
portable); separate GET then DEL (race window between calls, rejected).

### Decision 3: JSON encoding for SessionData
**Chosen:** JSON-marshal `gowebauthn.SessionData` before storing.
**Rationale:** All fields of `gowebauthn.SessionData` are exported and
JSON-serialisable. JSON is human-readable for debugging. Mirrors the BFF session
store pattern (`internal/bff/session_redis.go`).
**Alternatives considered:** Gob encoding (less portable, harder to debug);
Protobuf (overkill for internal-only ephemeral data).

### Decision 4: Key prefix `webauthn_session:`
**Chosen:** Redis keys use the prefix `webauthn_session:<key>`.
**Rationale:** Namespacing avoids collisions with other Redis data (e.g.
`bff_session:` used by the BFF session store). The key itself is the opaque
string supplied by the ceremony handler (256-bit CSPRNG `request_id` from §9).
**Alternatives considered:** No prefix (collision risk, rejected).

### Decision 5: Dev fallback to InMemorySessionStore
**Chosen:** When `REDIS_URL` is unset, keep `InMemorySessionStore` with an
updated comment referencing this plan.
**Rationale:** Allows local development without Redis. The existing
`InMemorySessionStore` is functionally correct for single-replica dev; only
multi-replica production requires Redis.
**Alternatives considered:** Require Redis always (harms dev ergonomics,
rejected).
