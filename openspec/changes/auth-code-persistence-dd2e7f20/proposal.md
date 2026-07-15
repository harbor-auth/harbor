# Proposal: Authorization Code Persistence (Redis-backed, multi-replica-safe)

## Problem

`cmd/harbor-hot/main.go` hard-wires `oidc.NewInMemoryAuthCodeStore()` even when
`DATABASE_URL` is configured — and logs an explicit SCAFFOLD warning:

> "authorization codes stored in-memory — not suitable for multi-replica deployment"

Authorization codes are short-lived (≤ 60s, §3.3) but must survive across any
replica that happens to handle the `/token` request after a different replica
handled `/authorize`. With in-memory storage, the code store is invisible to
other replicas: the exchange fails with `invalid_grant` non-deterministically
depending on which pod handles each request. This is a correctness hazard in any
horizontally-scaled deployment, not merely a performance concern.

Auth codes are also the target of the reuse-detection / theft signal already
implemented in `service.go` — a DB-backed store makes `Peek` / `Consume`
semantics transactionally correct across replicas (the in-memory store's atomic
`Peek`→`Consume` window is safe within one process but meaningless across replicas).

## Proposed Solution

Replace the in-memory code store with a **Redis-backed** implementation behind
the same `oidc.AuthCodeStore` interface (`Save`, `Peek`, `Consume`):

1. **`Save`** — Serialize the `AuthCode` struct (JSON) and `SET NX EX <ttl>` in
   Redis keyed by `auth_code:<code>`.
2. **`Peek`** — `GET` the key; deserialize; return `(AuthCode, found, consumed, error)`.
   The consumed flag is encoded in a separate key `auth_code_consumed:<code>` (SET EX)
   so Peek can distinguish "not found" (expired or never existed) from "already consumed".
3. **`Consume`** — Lua script: atomically read the code, check the consumed marker,
   set the consumed marker, return `ConsumeResult`. Lua guarantees atomicity so
   two concurrent `/token` requests for the same code cannot both succeed.
4. **`Expiry`** — Codes expire naturally at their `ExpiresAt` TTL; no cleanup job needed.
   Consumed-marker TTL = 2× code TTL so reuse-detection fires even near expiry.

Redis is the right store here — not Postgres — because:
- Auth codes are ephemeral (60s TTL); long-term persistence adds cost with no benefit.
- `SET NX` + Lua scripts give the atomicity needed for `Consume` without a database transaction.
- Redis is already implied by §4.1's hot-path architecture.

Dev fallback: when `REDIS_URL` is not set, keep the in-memory store with a
deprecation warning (existing behaviour).

## Non-Goals

- Database-backed auth code store (Redis is the right fit for ephemeral codes).
- Session family revocation by auth code (separate feature).
- Custom serialization formats (JSON is sufficient for this use case).

## Success Criteria

- [ ] `RedisAuthCodeStore` implements `oidc.AuthCodeStore` interface.
- [ ] `Save` uses `SET NX EX` with code TTL.
- [ ] `Peek` reads code without mutating consumed state.
- [ ] `Consume` uses Lua script for atomic check-and-mark.
- [ ] Consumed-marker TTL = 2× code TTL for reliable reuse detection.
- [ ] `cmd/harbor-hot/main.go` wires `RedisAuthCodeStore` when `REDIS_URL` is set.
- [ ] Integration tests with miniredis cover: save→peek→consume, double-consume, expiry.
- [ ] No plaintext PII in Redis keys/values beyond opaque fields.
- [ ] `make agent-check` clean.
