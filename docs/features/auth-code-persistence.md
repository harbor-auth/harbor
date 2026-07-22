---
title: Authorization Code Persistence (Redis-backed, multi-replica-safe)
status: implemented
design_refs: [§4.1, §4.4, §10]
code:  [internal/clients/, cmd/harbor-hot/]
spec:  []
tests: [internal/clients/]
depends_on: [oidc-authorization-code]
plan: auth-code-persistence
last_reconciled: 2026-07-21
---

# Authorization Code Persistence (Redis-backed, multi-replica-safe)

## Summary

Harbor stores OAuth authorization codes in **Redis** behind the existing
`oidc.AuthCodeStore` seam, so the `/authorize`→`/token` handshake survives
across replicas (docs/DESIGN.md §4.1 — the hot path is stateless and
horizontally scalable). Before this, `cmd/harbor-hot` hard-wired
`oidc.NewInMemoryAuthCodeStore()` and logged a SCAFFOLD warning: a code saved by
the replica that served `/authorize` was invisible to whichever replica served
`/token`, so the exchange failed with `invalid_grant` non-deterministically
under any multi-pod deployment. `clients.RedisAuthCodeStore` closes that gap
with TTL-based expiry and an **atomic Lua `Consume`** that makes single-use /
reuse-detection semantics correct *across* replicas, not merely within one
process.

## Behavior (as-built)

**`Save` (single-use guard)** — serializes the `oidc.AuthCode` to JSON and
writes it with `SET NX EX` under `authcode:<code>`. `NX` means a second `Save`
of the same code value fails, and the `EX` TTL (60 s in the hot-path wiring,
§3.3) expires the code naturally with no cleanup job.

**`Peek` (non-mutating read)** — a Redis pipeline does `GET authcode:<code>` +
`EXISTS authcode:consumed:<code>` in one round-trip and returns
`(AuthCode, found, consumed, error)`. A missing code key returns
`found=false`; a present consumed marker returns `consumed=true`, letting the
caller distinguish "never existed / expired" from "already redeemed".

**`Consume` (atomic redeem + reuse detection)** — a pinned Lua script runs
check-and-mark atomically inside Redis, so two concurrent `/token` requests for
the same code cannot both win:

- code key absent → `ConsumeNotFound`
- consumed marker absent → set it (`SET EX`) and return `ConsumeFirstUse` with
  the decoded `AuthCode`
- consumed marker present → return `ConsumeReused` with the decoded `AuthCode`
  (feeds the theft/reuse signal in `oidc/service.go`)

The **consumed marker TTL is 2× the code TTL**, so the reuse-detection signal
still fires for a redeem that races code expiry (a first `Consume` near the TTL
boundary can't silently look like a fresh code to a second attacker request).

**Wiring & dev fallback** — `cmd/harbor-hot/main.go` selects the store from
`REDIS_URL`: present → `clients.NewRedisAuthCodeStore(redisClient, 60s)`; absent
→ `oidc.NewInMemoryAuthCodeStore()` with a warning that in-memory is not
multi-replica-safe. The Redis client constructor returns `(nil, nil)` when
`REDIS_URL` is unset, so dev/test runs need no Redis. The original
"authorization codes stored in-memory" **SCAFFOLD warning is gone** from the
Redis path.

## Interfaces / Endpoints

No new HTTP surface — this is a storage-backend swap behind an existing
interface. Exported Go surface:

- `clients.NewRedisAuthCodeStore(client *redis.Client, codeTTL time.Duration) *clients.RedisAuthCodeStore`
- `clients.RedisAuthCodeStore` implements `oidc.AuthCodeStore`
  (`Save`, `Peek`, `Consume`) — enforced by a compile-time
  `var _ oidc.AuthCodeStore = (*RedisAuthCodeStore)(nil)` assertion.

Redis key layout:

| Key | Value | TTL |
|---|---|---|
| `authcode:<code>` | JSON-encoded `oidc.AuthCode` | code TTL (60 s) |
| `authcode:consumed:<code>` | `"1"` marker | 2× code TTL |

## Code map

| Path | Role |
|---|---|
| `internal/clients/codes.go` | `RedisAuthCodeStore` — `Save` (SET NX EX), `Peek` (pipelined GET + consumed EXISTS), `Consume` (atomic Lua `consumeScript`, statuses 0/1/2). |
| `internal/clients/codes_test.go` | Round-trip `Save`→`Peek`→`Consume`; double-consume → `ConsumeReused`; missing/expired → `ConsumeNotFound`; consumed-marker TTL. |
| `cmd/harbor-hot/main.go` | Selects `RedisAuthCodeStore` when `REDIS_URL` is set; in-memory dev fallback otherwise; the old SCAFFOLD warning removed from the Redis path. |

## Security & privacy invariants

- **Single-use codes (§3.3)** — `Save` uses `SET NX`; `Consume`'s Lua script is
  atomic, so a code is redeemable exactly once even under concurrent `/token`
  requests across replicas.
- **Reuse detection survives expiry** — the consumed marker outlives the code
  (2× TTL), so a replayed code is reported `ConsumeReused` (theft signal) rather
  than silently `ConsumeNotFound`.
- **No PII at rest (§4.4)** — stored values are the opaque `AuthCode` (code
  value, PPID `sub`, scopes, `ExpiresAt`); no raw user PII. Codes are ephemeral
  (≤ 60 s) and TTL-expired.
- **Fail-safe availability (§4.1)** — a Redis outage fails the affected login /
  exchange closed (recoverable by retry); it never downgrades to a
  cross-replica-inconsistent in-memory store when `REDIS_URL` is configured.

## Tests

`internal/clients/codes_test.go` (miniredis) — `Save`→`Peek`→`Consume`
round-trip; first `Consume` → `ConsumeFirstUse`, second → `ConsumeReused`;
absent/expired code → `ConsumeNotFound`; consumed marker present after first
redeem with the doubled TTL; JSON round-trip preserves the `AuthCode` fields.
`go test ./internal/clients/...` green.

## Known gaps / TODOs

- **`RevokeBySession` family-delete** — the plan sketched an
  `auth_code_by_session:<session_id>` family key for session-scoped bulk
  revocation. The shipped store implements the single-code single-use +
  reuse-detection contract; session-family revocation of *unredeemed* codes is
  not yet wired (unredeemed codes still self-expire at their 60 s TTL, so the
  exposure window is bounded).
- **Lua compatibility** — `Consume` uses inline `EVAL` (`redis.NewScript`) for
  broad Redis-version compatibility rather than `FUNCTION LOAD`.
- **miniredis vs real Redis** — unit tests use hermetic miniredis; the Lua path
  is additionally exercised against real Redis in the e2e Docker Compose stack.
