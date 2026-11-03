---
title: Authorization Code Persistence (Redis-backed, multi-replica-safe)
status: implemented
design_refs: [§4.1, §4.4, §10]
code: [internal/oidc/, internal/clients/, cmd/harbor-hot/]
spec: []
tests: [internal/clients/, internal/oidc/, internal/oidcapi/]
depends_on: [oidc-authorization-code]
plan: auth-code-persistence
last_reconciled: 2026-11-03
---

# Authorization Code Persistence

Harbor stores authorization codes in Redis so every replica observes the same
single-use and replay state. Production and authorization-code tests use the
same `oidc.RedisAuthCodeStore` implementation. The existing `clients` constructor
forwards to that implementation. There is no in-memory authorization-code store
or development fallback.

## Storage behavior

`Save` writes JSON under `authcode:<code>` using `SET NX` with the configured
TTL (60 seconds in production). Saving an existing code fails.

`Peek` atomically reads the code and consumed marker using `MGET`, returning
its binding and consumed state without modifying either TTL.

`Consume` uses a Lua script to atomically check and mark redemption:

- Missing metadata returns `ConsumeNotFound`.
- First use creates `authcode:consumed:<code>` and extends the metadata TTL to
  the same replay window: twice the configured code TTL from redemption.
- Subsequent use returns `ConsumeReused` with the original binding. Replays
  never extend either TTL.

The OIDC service independently enforces `AuthCode.ExpiresAt`. Retaining consumed
metadata permits replay detection after the code's original expiry; it does not
permit another token exchange. Replay revocation requires valid client
credentials, client/redirect binding, and PKCE before it can affect a token family.

| Key | Value | Retention |
|---|---|---|
| `authcode:<code>` | JSON `oidc.AuthCode` | Code TTL while unspent; twice code TTL from first redemption once consumed |
| `authcode:consumed:<code>` | `"1"` | Twice code TTL from first redemption |

Redis errors fail the exchange closed. Production wires Redis directly and
never selects a process-local fallback.

## Tests

Install `redis-server` or use `nix develop`, which supplies it. Tests start
isolated real Redis processes with Unix sockets, no TCP listeners, and no disk
persistence; cleanup terminates each process and removes its directory. Missing
Redis fails the test instead of skipping it or substituting an emulator.

`go test ./...` exercises the production adapter in OIDC service, HTTP API, and
BFF tests. Storage tests cover duplicate saves, concurrent redemption, actual
expiry, and retention of consumed bindings beyond the original TTL. The service
regression checks authenticated replay revocation after actual code expiry and
rejects attempts to revoke using incorrect credentials, bindings, or PKCE.

Other test collaborators, including session and grant helpers, are separate from
authorization-code storage and remain in the test-support packages.

## Remaining scope

Bulk deletion of unredeemed codes by session is not implemented. Unredeemed
codes expire at their configured TTL. Replay metadata is also bounded by its
TTL; it cannot identify replays after the retention window ends.
