---
title: WebAuthn session persistence (Redis-backed, multi-replica-safe)
status: promoted
design_refs: [§4.1, §4.4, §9, §11.1]
targets: [internal/webauthn/, cmd/harbor-mgmt/]
promoted_to: docs/features/webauthn-session-store.md
openspec: changes/webauthn-session-store
created: 2026-07-17
---

# WebAuthn session persistence (plan)

> **Dependency order:** *No prerequisites.* The `SessionStore` interface and
> `InMemorySessionStore` already exist; this plan swaps in a durable backend.
> Can land in parallel with `auth-code-persistence` and
> `bff-session-middleware`. Must land before any multi-replica deployment
> involving WebAuthn ceremonies.

## Problem

`internal/webauthn/store.go` hard-wires `NewInMemorySessionStore()` for
WebAuthn ceremony sessions, and the code carries an explicit production warning:

> "Production wiring should use a shared, short-TTL store (e.g. Redis;
> docs/DESIGN.md §4.4) so the ceremony works across replicas."

WebAuthn ceremonies are two-step: `POST /login` (Begin) calls
`BeginAssertion` and saves a `gowebauthn.SessionData` challenge under an
opaque key; `POST /login/complete` (Finish) calls `Take` to retrieve-and-delete
the challenge and pass it to `FinishAssertion`. When `harbor-mgmt` runs with
more than one replica, the Begin request might land on replica A while the
Finish request lands on replica B. With in-memory storage, replica B has no
record of the challenge and the ceremony fails non-deterministically with
`ErrSessionNotFound` depending on pod routing.

Ceremony sessions are short-lived (5-minute TTL) and single-use (`Take` deletes
on read). That profile makes Redis the right store: ephemeral data, atomic
read-delete, no long-term persistence benefit.

## Proposed approach

Implement `RedisSessionStore` behind the same `webauthn.SessionStore` interface
(`Save`, `Take`):

1. **`Save`** — JSON-marshal the `gowebauthn.SessionData` struct and `SET NX EX
   <ttl>` in Redis keyed by `webauthn_session:<key>`. The `NX` flag prevents a
   second Begin call for the same key from overwriting an in-flight challenge
   (race-safe).

2. **`Take`** — Lua script: atomically `GET` the key, then `DEL` the key, then
   return the value. The Lua atomicity guarantee means two concurrent Finish
   calls for the same session cannot both succeed: the first wins, the second
   receives `ErrSessionNotFound`. A nil GET result (absent or already taken)
   also returns `ErrSessionNotFound`.

Key format: `webauthn_session:<key>` where `<key>` is the opaque string
supplied by the ceremony handler. In the BFF session model this is the
`request_id` (256-bit CSPRNG, §9); the same entropy requirement applies here.

TTL: 5 minutes, matching `InMemorySessionStore` and the BFF session TTL.
The browser must complete the full passkey ceremony within this window.

Dev fallback: when `REDIS_URL` is unset, keep `InMemorySessionStore` with the
existing comment updated to point at this plan's slug.

## DESIGN alignment

Realises §4.1 (hot-path nodes stateless across replicas — mgmt-side session
challenges now survive any pod) and §4.4 (no PII at rest beyond opaque
challenge bytes; `gowebauthn.SessionData` contains the challenge nonce, allowed
credential IDs, and RPID — no user PII such as email or name). The one-time-use
`Take` semantic matches §9's BFF session lifecycle model (short-lived,
single-use). Does **not** change `DESIGN.md`.

## Target code paths

- `internal/webauthn/store.go` — `SessionStore` interface (no change needed)
- `internal/webauthn/store_redis.go` — `RedisSessionStore implements SessionStore`
- `internal/webauthn/store_redis_test.go` — integration tests (miniredis or test container)
- `cmd/harbor-mgmt/main.go` — wire `RedisSessionStore` when `REDIS_URL` is set;
  keep `InMemorySessionStore` for no-Redis dev mode

## Implementation checklist

- [x] `RedisSessionStore` struct wrapping `*redis.Client` + `sessionTTL time.Duration`.
- [x] `Save(ctx, key, data)` — JSON-marshal `gowebauthn.SessionData`; `SET NX EX
  <ttl>`. Return an error if the key already exists (NX failed).
- [x] `Take(ctx, key)` — Lua script: `GET key` → `DEL key` → `return value`.
  Return `ErrSessionNotFound` when result is nil.
- [x] Lua script must handle the concurrent-request case: GET then DEL is
  atomic at the script level; two concurrent `Take` calls cannot both retrieve
  the value.
- [x] Validate that all fields of `gowebauthn.SessionData` survive a JSON
  round-trip (all fields are exported in the upstream library; verify against
  the pinned version in `go.mod`).
- [x] Integration tests (miniredis preferred; fallback real Redis in CI):
  - `Save` → `Take` round-trip preserves all `SessionData` fields.
  - Double-`Take` returns `ErrSessionNotFound` on the second call.
  - Expired session (TTL elapsed) returns `ErrSessionNotFound`.
  - `Save` with duplicate key returns an error (NX guard).
  - Concurrent `Take` calls: only one succeeds.
- [x] Wire `RedisSessionStore` into `cmd/harbor-mgmt/main.go` when `REDIS_URL`
  is set; keep `InMemorySessionStore` for dev (no-Redis path).
- [x] Update the `InMemorySessionStore` production-warning comment to reference
  this plan slug (`webauthn-session-store`).
- [x] Tests: confirm no PII in Redis keys or values; TTL fires correctly; Lua
  atomicity serialises concurrent `Take` calls.
- [x] Author & verify paired OpenSpec change: `openspec validate webauthn-session-store --strict`
- [x] Reconcile & promote: `@plan promote webauthn-session-store`

> **Promoted (2026-07-20):** shipped via PR #39 (rebased clean onto main; CI
> green — agent-check, helm-lint, e2e). As-built behaviour is documented in
> [docs/features/webauthn-session-store.md](../features/webauthn-session-store.md).
> A fail-closed default TTL was added during landing: a non-positive
> `sessionTTL` is coerced to 5 min so expiry can never be accidentally disabled.

## Risks & open questions

- **`gowebauthn.SessionData` JSON encoding**: the struct is from a third-party
  library (`github.com/go-webauthn/webauthn`). Check the pinned version in
  `go.mod` to confirm all relevant fields (`Challenge`, `UserID`,
  `AllowedCredentialIDs`, `Expires`, `UserVerification`, `RelyingPartyID`) are
  exported and JSON-serialisable. If any are unexported or use custom
  marshallers, wrap with a local adapter struct.
- **Key collision**: the ceremony key must be globally unique across concurrent
  ceremonies. When driven by the BFF session, the `request_id` (256-bit CSPRNG)
  satisfies this. Any other key source must provide equivalent entropy.
- **Redis availability**: a Redis outage during Begin fails ceremony start;
  during Finish it also fails. Both are user-recoverable (retry login within the
  BFF session TTL). Document the availability dependency in the operations
  runbook.
- **miniredis Lua fidelity**: miniredis supports most Lua primitives but
  diverges on some edge cases. Keep the Lua script minimal (`GET` + `DEL` +
  `return`). Run the concurrency path against a real Redis instance in the
  Docker Compose e2e environment to confirm atomicity.
- **Alternative — Postgres**: functionally viable (short-lived rows with a GC
  job) but adds a write + read-delete on every ceremony to the hot-path DB.
  Redis TTL-based expiry with no cleanup job is the better operational fit for
  5-minute ephemeral data.

## Definition of done

`go build/vet/test ./...` green; `cmd/harbor-mgmt` wires `RedisSessionStore`
when `REDIS_URL` is set; concurrent `Take` is atomic (Lua); expired session
returns `ErrSessionNotFound`; double-`Take` returns `ErrSessionNotFound`; no
plaintext PII in Redis keys or values; `make agent-check` clean. The
`InMemorySessionStore` warning comment references this plan slug. Ready to
`@plan promote`.
