---
title: Authorization code persistence (Redis-backed, multi-replica-safe)
status: approved
design_refs: [§4.1, §4.4, §10]
targets: [internal/oidc/, internal/clients/, cmd/harbor-hot/]
promoted_to: null
openspec: changes/auth-code-persistence
created: 2026-07-14
---

# Authorization code persistence (plan)

> **Dependency order:** *No prerequisites.* The `AuthCodeStore` interface and
> `InMemoryAuthCodeStore` already exist; this plan swaps in a durable backend.
> Can land in parallel with any other plan. Must land before any multi-replica
> deployment.

## Problem

`cmd/harbor-hot/main.go` hard-wires `oidc.NewInMemoryAuthCodeStore()` even when
`DATABASE_URL` is configured — and logs an explicit SCAFFOLD warning:

> "authorization codes stored in-memory — not suitable for multi-replica deployment"

Authorization codes are short-lived (≤ 60 s, §3.3) but must survive across any
replica that happens to handle the `/token` request after a different replica
handled `/authorize`. With in-memory storage, the code store is invisible to
other replicas: the exchange fails with `invalid_grant` non-deterministically
depending on which pod handles each request. This is a correctness hazard in any
horizontally-scaled deployment, not merely a performance concern.

Auth codes are also the target of the reuse-detection / theft signal already
implemented in `service.go` — a DB-backed store makes `Peek` / `Consume`
semantics transactionally correct across replicas (the in-memory store's atomic
`Peek`→`Consume` window is safe within one process but meaningless across replicas).

## Proposed approach

Replace the in-memory code store with a **Redis-backed** implementation behind
the same `oidc.AuthCodeStore` interface (`Peek`, `Consume`, `Save`):

1. **`Save`** — serialize the `AuthCode` struct (JSON or MessagePack) and `SET
   NX EX <ttl>` in Redis keyed by `auth_code:<code>` and a second key
   `auth_code_by_session:<session_id>` (for family revocation).
2. **`Peek`** — `GET` the key; deserialize; return `(AuthCode, found, consumed,
   error)`. The consumed flag is encoded in a separate key
   `auth_code_consumed:<code>` (SET EX) so Peek can distinguish
   "not found" (expired or never existed) from "already consumed".
3. **`Consume`** — Lua script: atomically read the code, check the consumed
   marker, write the consumed marker, return `ConsumeResult`. Lua guarantees
   atomicity so two concurrent `/token` requests for the same code cannot both
   succeed.
4. **`Expiry`** — codes expire naturally at their `ExpiresAt` TTL; no cleanup
   job needed. Set `EX` on both the code key and the consumed marker so the
   consumed marker outlives the code by a small window (e.g. 2× the code TTL)
   to guarantee the reuse-detection signal fires even if the first `Consume` raced
   with expiry.
5. **`RevokeBySession`** — for auth-code-reuse theft signal: the family key
   `auth_code_by_session:<session_id>` maps to a list of code keys so all codes
   from a session can be deleted together.

Redis is the right store here — not Postgres — because:
- Auth codes are ephemeral (60 s TTL); long-term persistence adds cost with no
  benefit.
- `SET NX` + Lua scripts give the atomicity needed for `Consume` without a
  database transaction.
- Redis is already implied by §4.1's hot-path architecture (CDN-cacheable JWKS,
  edge-colocated session lookups); the same regional Redis instance serves both.

Dev fallback: when neither `REDIS_URL` nor `DATABASE_URL` is set, keep the
in-memory store with a louder deprecation warning (existing behaviour).

## DESIGN alignment

Realises §4.1 (hot path stateless across replicas), §4.4 (no PII at rest in
Redis beyond the short-lived code; codes contain only opaque `sub` / scopes, no
raw PII), and §10's principle that regional stores are the consistency boundary.
Does **not** change `DESIGN.md`.

## Target code paths

- `internal/oidc/store.go` — `AuthCodeStore` interface (already exists; no change expected)
- `internal/clients/codes.go` — `RedisAuthCodeStore implements oidc.AuthCodeStore`
- `internal/clients/codes_test.go` — integration tests (real Redis via `miniredis` or a test container)
- `cmd/harbor-hot/main.go` — wire `RedisAuthCodeStore` when `REDIS_URL` is set

## Implementation checklist

- [ ] Add `go.mod` dependency on `github.com/redis/go-redis/v9` (or `miniredis` for tests).
- [ ] `RedisAuthCodeStore`: `Save` (SET NX EX), `Peek` (GET + consumed check), `Consume` (Lua atomic), `RevokeBySession` (family delete).
- [ ] Lua script for atomic `Consume`: read code → check consumed marker → set consumed marker → return result; covers `ConsumeOK`, `ConsumeReused`, `ConsumeNotFound` correctly.
- [ ] Consumed-marker TTL = 2× code TTL so reuse-detection fires even near expiry.
- [ ] Integration tests (miniredis): round-trip `Save`→`Peek`→`Consume`; double-consume returns `ConsumeReused`; expired code returns `ConsumeNotFound`; `RevokeBySession` deletes all family keys.
- [ ] Wire `RedisAuthCodeStore` into `cmd/harbor-hot/main.go` when `REDIS_URL` is set; keep `InMemoryAuthCodeStore` for `DATABASE_URL`-absent dev mode (remove the SCAFFOLD warning once real wiring is in place).
- [ ] Update the existing SCAFFOLD comment/warning in `main.go` to point at this plan's slug once it ships.
- [ ] Tests: no PII in stored keys/values beyond opaque fields; expiry fires correctly; concurrent `Consume` calls are serialised by Lua script.
- [ ] Author & verify paired OpenSpec change: `openspec validate auth-code-persistence --strict`
- [ ] Reconcile & promote: `@plan promote auth-code-persistence`

## Risks & open questions

- **Redis availability**: a Redis outage during `/authorize` fails the login
  (code cannot be saved); during `/token` fails the exchange. Both are
  recoverable (retry login). Document the availability dependency clearly.
- **Lua script size**: keep the Lua script small and pinned (Redis 7+ supports
  `FUNCTION LOAD`; for compatibility prefer inline `EVAL`).
- **Alternative — Postgres-backed codes**: simpler operationally (one fewer
  dependency) but adds a write on every `/authorize` and a read+write on every
  `/token` — both hot-path operations. Redis TTL-expiry is a better fit for
  ephemeral codes. Postgres can be revisited if operational complexity is a
  concern.
- **miniredis vs real Redis in tests**: miniredis is hermetic and fast but does
  not exercise Lua behaviour identically. Run the Lua-path tests against a real
  Redis in CI via Docker Compose (already used for e2e tests).

## Definition of done

`go build/vet/test ./...` green; `cmd/harbor-hot` wires `RedisAuthCodeStore`
when `REDIS_URL` is set; concurrent `Consume` is atomically correct (Lua);
expired code returns `ConsumeNotFound`; double-consume returns `ConsumeReused`;
no plaintext PII in Redis keys or values; `make agent-check` clean. The SCAFFOLD
warning in `main.go` is gone. Ready to `@plan promote`.
