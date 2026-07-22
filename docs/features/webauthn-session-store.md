---
title: WebAuthn Session Store (Redis-backed, multi-replica-safe)
status: implemented
design_refs: [§4.1, §4.4, §9, §11.7]
code:  [internal/webauthn/, cmd/harbor-mgmt/]
spec:  []
tests: [internal/webauthn/]
depends_on: [webauthn-passkeys]
plan: webauthn-session-store
last_reconciled: 2026-07-20
---

# WebAuthn Session Store (Redis-backed, multi-replica-safe)

## Summary

Harbor persists WebAuthn ceremony sessions (the challenge held between the
`Begin` and `Finish` steps of a passkey ceremony) in **Redis**, so the ceremony
survives when `Begin` and `Finish` land on different `harbor-mgmt` replicas
(§4.1 — mgmt-side session state is no longer pinned to a single pod).
`webauthn.RedisSessionStore` implements the existing `webauthn.SessionStore`
seam (`Save`/`Take`) with `SET NX EX` for race-safe writes and an atomic
`GET`+`DEL` Lua script for one-time-use reads, replacing the process-local
`InMemorySessionStore` that failed non-deterministically under multi-replica
routing. Sessions are short-lived (5-minute TTL) and single-use, matching the
BFF session lifecycle (§9).

## Behavior (as-built)

**Save (`SET NX EX`)** — `Save(ctx, key, data)` JSON-marshals the
`gowebauthn.SessionData` and writes it under `webauthn_session:<key>` with
`SET NX EX <ttl>`. The `NX` flag makes the write **race-safe**: a second `Begin`
for the same key cannot overwrite an in-flight challenge — it returns
`ErrSessionExists` instead. The `EX` expiry means challenges self-expire; there
is no cleanup job.

**Take (atomic `GET`+`DEL`)** — `Take(ctx, key)` runs a Lua script that `GET`s
the key, `DEL`s it, and returns the value, all atomically. This guarantees
**one-time-use replay defense**: two concurrent `Finish` calls for the same
session cannot both succeed — the first wins, the second receives
`ErrSessionNotFound`. An absent/already-taken/expired key also returns
`ErrSessionNotFound`.

**Fail-closed default TTL** — `NewRedisSessionStore(client, sessionTTL)` coerces
a non-positive `sessionTTL` to a 5-minute default. A zero TTL would make
`SET NX EX` store the key with **no** expiration (unbounded, replayable
challenges); coercing it closed means ceremony-session expiry can never be
accidentally disabled.

**Wiring & fallback (`cmd/harbor-mgmt`)** — the mgmt binary wires
`RedisSessionStore` when `REDIS_URL` is set (sharing the same Redis client as the
BFF session store), and falls back to `InMemorySessionStore` with an explicit
dev-only warning when it is not. A **configured-but-unreachable** Redis is
**fatal at startup** — mirroring the DB-connection guard — so a production
misconfiguration surfaces immediately rather than silently degrading to a store
that isn't shared across replicas.

## Interfaces / Endpoints

- No new HTTP endpoints — the passkey `Begin`/`Finish` ceremony surface is
  unchanged; only the session backend behind it changed.
- Exported Go surface:
  - `webauthn.NewRedisSessionStore(client *redis.Client, sessionTTL time.Duration) *RedisSessionStore`
    (implements `webauthn.SessionStore`).
  - `webauthn.ErrSessionExists` (NX guard on `Save`).
  - Existing `webauthn.SessionStore`, `webauthn.ErrSessionNotFound`,
    `webauthn.NewInMemorySessionStore()` (dev fallback) — unchanged contract.
- Storage: Redis keys `webauthn_session:<key>`, JSON-encoded
  `gowebauthn.SessionData`, 5-minute TTL.

## Code map

| Path | Role |
|---|---|
| `internal/webauthn/store_redis.go` | `RedisSessionStore` — `SET NX EX` save, atomic `GET`+`DEL` Lua take, fail-closed default TTL. |
| `internal/webauthn/store.go` | `SessionStore` interface + `InMemorySessionStore` dev fallback (production-warning comment points here). |
| `cmd/harbor-mgmt/main.go` | Wires `RedisSessionStore` when `REDIS_URL` is set; in-memory fallback otherwise; unreachable-but-configured Redis is fatal. |

## Security & privacy invariants

- **One-time-use challenges (§11.7)** — the atomic `GET`+`DEL` Lua script makes
  `Take` single-use; a challenge can never be replayed, and concurrent `Finish`
  calls cannot both consume the same session.
- **Race-safe writes** — `SET NX` prevents a second `Begin` from clobbering an
  in-flight challenge (`ErrSessionExists`).
- **Bounded lifetime, fail-closed** — every session carries a TTL; a
  non-positive configured TTL is coerced to 5 min, so expiry can never be
  disabled (no unbounded/replayable challenges).
- **No PII at rest (§4.4)** — Redis holds only the opaque challenge nonce,
  allowed credential IDs, and RPID from `gowebauthn.SessionData`; no user PII
  (email/name). Keys are opaque (`webauthn_session:<opaque-key>`).
- **Multi-replica correctness (§4.1)** — ceremony state is shared across mgmt
  replicas, so `Begin`/`Finish` can land on different pods.

## Tests

`internal/webauthn/store_redis_test.go` (miniredis, no external Redis needed):

- `Save`→`Take` round-trip preserves all `SessionData` fields (incl. binary
  `UserID` and 32-byte challenge fidelity).
- Double-`Take` returns `ErrSessionNotFound` (one-time-use).
- Expired session (TTL fast-forwarded) returns `ErrSessionNotFound`.
- Duplicate `Save` returns `ErrSessionExists` (NX guard) and preserves the
  original.
- Concurrent `Take` (10 goroutines) — exactly one succeeds (Lua atomicity).
- Key-prefix assertion (`webauthn_session:<key>`).
- Zero-TTL coercion — a `0` TTL still yields a positive key TTL (fail-closed).

## Known gaps / TODOs

- **Redis availability** — a Redis outage fails ceremony `Begin`/`Finish`; both
  are user-recoverable (retry login within the session TTL). The availability
  dependency belongs in the operations runbook.
- **miniredis Lua fidelity** — the concurrency path is validated against
  miniredis; the Lua script is kept minimal (`GET`+`DEL`+`return`). Running the
  concurrency path against a real Redis in the Docker Compose e2e environment is
  a follow-up hardening.
- Consumes the passkey ceremony from [webauthn-passkeys](webauthn-passkeys.md);
  the ceremony key is supplied by the caller (the BFF `request_id`, a 256-bit
  CSPRNG, once [bff-session-middleware](../plans/bff-session-middleware.md)
  drives login).
