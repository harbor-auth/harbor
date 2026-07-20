# Proposal: WebAuthn session persistence (Redis-backed, multi-replica-safe)

## Problem

`internal/webauthn/store.go` hard-wires `NewInMemorySessionStore()` for WebAuthn
ceremony sessions. The code carries an explicit production warning:

> "Production wiring should use a shared, short-TTL store (e.g. Redis;
> docs/DESIGN.md §4.4) so the ceremony works across replicas."

WebAuthn ceremonies are two-step: `POST /login` (Begin) saves a
`gowebauthn.SessionData` challenge under an opaque key; `POST /login/complete`
(Finish) retrieves-and-deletes the challenge via `Take`. When `harbor-mgmt`
runs with multiple replicas, Begin might land on replica A while Finish lands
on replica B — with in-memory storage, replica B has no record and the ceremony
fails non-deterministically with `ErrSessionNotFound`.

Ceremony sessions are short-lived (5-minute TTL) and single-use (`Take` deletes
on read). That profile makes Redis the right store: ephemeral data, atomic
read-delete, no long-term persistence benefit.

## Proposed Solution

Implement `RedisSessionStore` behind the same `webauthn.SessionStore` interface
(`Save`, `Take`):

- **`Save`** — JSON-marshal `gowebauthn.SessionData` and `SET NX EX <ttl>` in
  Redis keyed by `webauthn_session:<key>`. The `NX` flag prevents a second Begin
  call from overwriting an in-flight challenge (race-safe).

- **`Take`** — Lua script: atomically `GET` the key, then `DEL` the key, then
  return the value. Two concurrent Finish calls cannot both succeed: the first
  wins, the second receives `ErrSessionNotFound`.

Dev fallback: when `REDIS_URL` is unset, keep `InMemorySessionStore`.

## Non-Goals

- Postgres-backed sessions (Redis TTL-based expiry with no cleanup job is the
  better operational fit for 5-minute ephemeral data).
- Full hosted login UI (programmatic ceremony is enough for v1).
- HSM integration for session data (sessions contain no long-term secrets).

## Success Criteria

- [ ] `RedisSessionStore` implements `webauthn.SessionStore` (`Save`, `Take`).
- [ ] `Save` uses `SET NX EX` for race-safe, TTL-bound storage.
- [ ] `Take` uses Lua atomic `GET+DEL` for one-time-use semantics.
- [ ] Double-`Take` returns `ErrSessionNotFound`; expired sessions also return `ErrSessionNotFound`.
- [ ] `cmd/harbor-mgmt` wires `RedisSessionStore` when `REDIS_URL` is set.
- [ ] `make agent-check` clean.
