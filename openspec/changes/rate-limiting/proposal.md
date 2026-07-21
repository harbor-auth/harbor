# Proposal: Per-client hot-path rate limiting (abuse & enumeration defense)

## Problem

Harbor's stateless hot path (`harbor-hot`) exposes abuse-sensitive endpoints
that are currently unthrottled:

- **`POST /introspect`** (RFC 7662) reveals token validity to authenticated
  clients. Without per-client limits, a malicious or compromised client can
  enumerate token validity at high volume. The `token-introspection` change
  explicitly defers this control to this change.
- **`POST /token`** — the code and refresh exchanges can be hammered to probe
  `invalid_grant` vs success, or to brute-force short-lived authorization codes.
- **`GET/POST /authorize`** — repeated authorization attempts pressure the
  login ceremony (brute force / credential stuffing).
- **Unauthenticated DoS** — verification is intentionally cheap and DB-free
  (§4.1); the same cheapness makes an anonymous flood cheap to mount. §6.1
  (performance) and §11.7 (error cases / abuse) call for a bounded-cost
  response rather than unbounded work.

The hot path has no per-caller cost ceiling: the properties that make
verification cheap also make abuse cheap.

## Proposed Solution

Add a **Redis-backed, per-client + per-IP rate limiter** as hot-path middleware
in `internal/oidcapi/`, applied to `/introspect`, `/token`, and `/authorize`:

1. **Algorithm** — a Redis sliding-window (or token-bucket) counter keyed per
   identity. Each request atomically increments a windowed counter (Lua) and is
   rejected once the count exceeds the configured limit for the window.
2. **Keying** — per-**`client_id`** when the caller presents a registered
   client credential (Basic auth); anonymous / pre-auth requests fall back to a
   per-**IP** key. Per-client and per-IP buckets are independent.
3. **Response** — over-limit requests receive `429 Too Many Requests` with a
   `Retry-After` header (seconds to window reset) and a `rate_limited` error
   body consistent with the OAuth error envelope.
4. **Configuration** — per-route / per-identity limits are configurable via
   environment with sane defaults.
5. **Availability — fail-open** — on Redis unavailability the limiter allows
   the request (fail-open) to preserve hot-path availability (§4.1), but logs
   loudly and emits a metric. A limiter outage MUST NOT break verification.

## Non-Goals

- Exact distributed rate limiting (approximate limiting under high concurrency
  is sufficient for abuse defense).
- Fail-closed posture on Redis outage (rejected — availability of the hot path
  outweighs a temporary lapse in abuse controls; revisitable for `/introspect`).
- Global cross-region coordination (regional Redis only — no cross-region
  limiter state, preserving the edge-local hot path).
- Per-user (subject) rate limiting (this change is per-client / per-IP only).

## Success Criteria

- [ ] `RateLimiter` interface + `RedisRateLimiter` (Lua-atomic windowed counter).
- [ ] In-memory `RateLimiter` dev fallback when `REDIS_URL` is unset.
- [ ] Hot-path middleware extracts `client_id` (Basic auth) or falls back to per-IP.
- [ ] Middleware applied to `/introspect`, `/token`, `/authorize`.
- [ ] Over-limit returns `429` + `Retry-After` + `rate_limited` error body.
- [ ] Per-client and per-IP buckets are independent.
- [ ] Redis outage fails **open** (request allowed, logged, metered).
- [ ] `cmd/harbor-hot/main.go` wires the limiter when `REDIS_URL` is set.
- [ ] No PII in limiter keys beyond `client_id` / IP.
- [ ] `make agent-check` clean.
