# Design: Per-client hot-path rate limiting (Redis-backed)

## Key Decisions

### Decision 1: Redis sliding-window counter (over token-bucket)
**Chosen:** A Redis-backed **sliding-window** counter with a Lua-atomic window
roll (`INCR` + windowed key, or a sorted-set window), rejecting once the count
exceeds the configured limit for the window.
**Rationale:** Sliding-window gives smoother, more predictable limiting than a
fixed window (no boundary-burst doubling) and maps cleanly onto Redis TTL keys.
Lua guarantees the increment-and-check is atomic across replicas sharing the
regional Redis, so concurrent requests cannot both slip past the limit.
**Alternatives considered:** Token-bucket (also viable — smooth burst handling —
but needs per-key last-refill bookkeeping; kept as an implementation-equivalent
option behind the same interface); fixed-window (simplest, but allows 2× bursts
at window boundaries, rejected); in-process counters (not multi-replica-safe,
rejected for production).

### Decision 2: Per-client keying with per-IP fallback
**Chosen:** Key limits by **`client_id`** when the caller presents a registered
client credential (Basic auth on `/introspect` and `/token`); fall back to a
per-**IP** key for anonymous / pre-auth requests (e.g. `/authorize`). Per-client
and per-IP buckets are independent.
**Rationale:** The abuse actor for enumeration is a *client* (introspection
requires client auth), so `client_id` is the correct blast-radius boundary. IP
keying covers anonymous surfaces where no client identity exists yet. Keeping
the buckets independent prevents one noisy IP from exhausting a legitimate
client's budget and vice-versa.
**Alternatives considered:** IP-only (misattributes shared-NAT clients, rejected
for authenticated routes); subject-based (leaks nothing useful pre-auth and adds
PII to keys, rejected).

### Decision 3: Fail-open on Redis outage
**Chosen:** When Redis is unavailable, the limiter **allows** the request
(fail-open) but logs loudly and emits a metric.
**Rationale:** The hot path's core guarantee is cheap, always-available token
verification (§4.1). A rate-limiter dependency must never be able to take down
verification. A temporary lapse in abuse controls during a Redis outage is a
better failure mode than rejecting all traffic.
**Alternatives considered:** Fail-closed (rejects all traffic on Redis outage —
unacceptable availability coupling, rejected; may be revisited for `/introspect`
specifically if enumeration risk is judged to outweigh availability there).

### Decision 4: 429 Too Many Requests + Retry-After
**Chosen:** Over-limit requests return `429 Too Many Requests` with a
`Retry-After` header (seconds until window reset) and a `rate_limited` error
body consistent with the OAuth error envelope.
**Rationale:** `429` + `Retry-After` is the standard, client-actionable
signal; well-behaved clients back off automatically. `Retry-After` is clamped to
`[0, window]` and never negative; optional jitter avoids synchronized retry
storms.
**Alternatives considered:** Silent drop / connection reset (opaque to clients,
rejected); `503` (misrepresents the cause as server fault, rejected).

### Decision 5: Middleware placement on the hot-path router
**Chosen:** Implement the limiter as **`internal/oidcapi/` router middleware**
applied selectively to `/introspect`, `/token`, and `/authorize`; wire it in
`cmd/harbor-hot/main.go` when `REDIS_URL` is set.
**Rationale:** Middleware keeps limiting orthogonal to handler logic and lets
limits be applied per-route. Placing it in `oidcapi` (where the router and other
middleware already live) keeps the hot-path surface cohesive and avoids touching
handler internals.
**Alternatives considered:** Per-handler inline checks (duplicated, error-prone,
rejected); edge/LB-only limiting (can't key on `client_id` from Basic auth,
rejected as the sole control — complementary at best).
