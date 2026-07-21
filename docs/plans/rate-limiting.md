---
title: Per-client hot-path rate limiting (abuse & enumeration defense)
status: completed
design_refs: [§4.1, §6.1, §11.7]
targets: [internal/oidcapi/, internal/clients/, cmd/harbor-hot/]
promoted_to: null
openspec: changes/rate-limiting
created: 2026-07-20
---

# Per-client hot-path rate limiting (plan)

> **Dependency order:** depends **(hard)** on **`token-introspection`**. Rate
> limiting must protect the `POST /introspect` endpoint — the primary token
> *enumeration* surface — and that endpoint does not exist until
> `token-introspection` lands. The limiter is hot-path router middleware and
> shares the `internal/oidcapi/` router/middleware surface that
> `token-introspection` extends; building it first would fight that plan over
> the same files and leave the new endpoint unprotected. **Build after
> `token-introspection` is promoted.**

## Problem

Harbor's stateless hot path (`harbor-hot`) exposes several endpoints that are
abuse-sensitive but currently unthrottled:

- **Token enumeration via `/introspect`** — RFC 7662 introspection reveals
  token validity to authenticated clients. Without per-client rate limiting, a
  compromised or malicious client can enumerate token validity at high volume
  (the `token-introspection` plan explicitly defers this control here).
- **Token enumeration / brute force via `/token`** — the authorization-code and
  refresh-token exchanges can be hammered to probe `invalid_grant` vs success,
  or to brute-force short-lived codes.
- **Brute force / credential-stuffing pressure on `/authorize`** — repeated
  authorization attempts drive load onto the login ceremony.
- **Unauthenticated DoS on the stateless hot path** — because verification is
  intentionally cheap and DB-free (§4.1), an anonymous flood can still consume
  edge/compute capacity. §6.1 (performance) and §11.7 (error cases / abuse)
  both call for a bounded-cost abuse response rather than unbounded work.

Without a rate limiter, the hot path has no per-caller cost ceiling: the same
properties that make verification cheap (stateless, edge-cacheable) also make it
cheap to *abuse*.

## Proposed approach

Add a **Redis-backed, per-client + per-IP rate limiter** as hot-path middleware
in `internal/oidcapi/`, applied to the abuse-sensitive routes (`/introspect`,
`/token`, `/authorize`).

1. **Algorithm** — a Redis-backed **sliding-window (or token-bucket)** counter
   keyed per identity. Each request `INCR`s a windowed counter (Lua-atomic
   window roll) and is rejected when the count exceeds the configured limit for
   that window.
2. **Keying** — limits are keyed by **`client_id`** when the caller presents a
   registered client credential (Basic auth on `/introspect` and `/token`);
   anonymous or pre-auth requests (e.g. `/authorize`) fall back to a
   **per-IP** key. Per-client and per-IP limits are independent buckets.
3. **Response** — over-limit requests receive **`429 Too Many Requests`** with
   a **`Retry-After`** header (seconds until the window resets) and a
   `rate_limited` error body consistent with the OAuth error envelope.
4. **Configuration** — per-route and per-identity limits (requests / window)
   are configurable via environment (sane defaults baked in); no code change
   needed to tune limits per deployment.
5. **Availability posture — fail-open** — if Redis is unavailable, the limiter
   **fails open** (allows the request) to preserve hot-path availability
   (§4.1), but logs loudly and emits a metric so the outage is observable. A
   rate-limiter outage must never take down token verification.

## DESIGN alignment

Realises §4.1 (the limiter uses **regional Redis** — the same regional store as
sessions/auth-codes — with **no cross-region coordination**, preserving the
stateless, edge-local hot path), §6.1 (bounded per-caller cost under load), and
§11.7 (abuse/error-case handling: a defined `429` response instead of unbounded
work). Does **not** change `DESIGN.md` — §6.1 and §11.7 already anticipate
abuse controls on the hot path.

## Target code paths

- `internal/oidcapi/ratelimit.go` — new hot-path middleware (route wiring,
  `client_id`/IP key extraction, `429` + `Retry-After` response).
- `internal/clients/ratelimit.go` — `RedisRateLimiter` (Lua-atomic windowed
  counter behind a small `RateLimiter` interface; in-memory fallback for dev).
- `internal/clients/ratelimit_test.go` — limiter unit/integration tests
  (miniredis + real-Redis Lua path).
- `cmd/harbor-hot/main.go` — wire the limiter middleware when `REDIS_URL` is
  set; no-op (allow-all) middleware when unset in dev.

## Implementation checklist

- [ ] `RateLimiter` interface + `RedisRateLimiter` (Lua-atomic sliding-window / token-bucket `Allow(key, limit, window) (allowed bool, retryAfter time.Duration)`).
- [ ] In-memory `RateLimiter` dev fallback for when `REDIS_URL` is unset.
- [ ] `internal/oidcapi/ratelimit.go` middleware: extract `client_id` from Basic auth (per-client bucket) or fall back to per-IP; apply per-route limits.
- [ ] Apply middleware to `/introspect`, `/token`, `/authorize` on the hot-path router.
- [ ] `429 Too Many Requests` + `Retry-After` header + `rate_limited` error body on over-limit.
- [ ] Fail-open on Redis error (allow + log loudly + metric); never fail-closed on the hot path.
- [ ] Configurable per-route / per-identity limits via env with sane defaults.
- [ ] Wire limiter into `cmd/harbor-hot/main.go` when `REDIS_URL` is set.
- [ ] Tests: under-limit passes; over-limit returns `429` + `Retry-After`; per-client and per-IP buckets are independent; window resets; Redis outage fails open (request allowed).
- [ ] Tests: no PII in limiter keys (only `client_id` / hashed-or-raw IP, per privacy review).
- [ ] Author & verify paired OpenSpec change: `openspec validate rate-limiting --strict`
- [ ] Reconcile & promote: `@plan promote rate-limiting`

## Risks & open questions

- **Fail-open vs fail-closed** — this plan chooses **fail-open** on Redis
  outage to protect availability (§4.1), accepting that abuse controls lapse
  during a Redis outage. The tradeoff must be documented and alarmed; a
  fail-closed posture on `/introspect` specifically could be revisited if
  enumeration risk outweighs availability there.
- **Distributed-limiter accuracy across replicas** — a shared regional Redis
  gives a single source of truth, but window-roll races and clock skew can make
  the effective limit slightly higher than configured under high concurrency.
  Lua-atomic window operations bound this; exactness is a non-goal (approximate
  limiting is sufficient for abuse defense).
- **`Retry-After` semantics** — return seconds-until-window-reset; ensure it is
  never negative and is capped at the window length. Consider jitter to avoid
  synchronized retry storms.
- **Per-IP keying behind proxies** — the client IP must come from a trusted
  forwarded-header chain (edge/LB), not a spoofable header. Coordinate with the
  hot-path ingress config so per-IP buckets key on the real client IP.

## Definition of done

`go build/vet/test ./...` green; `/introspect`, `/token`, and `/authorize` are
rate-limited per-client (and per-IP for anonymous callers) via hot-path
middleware; over-limit requests return `429` with a correct `Retry-After`;
per-client and per-IP buckets are independent; a Redis outage fails **open**
(request allowed, logged, metered); no PII in limiter keys; `make agent-check`
clean. Ready to `@plan promote`.
