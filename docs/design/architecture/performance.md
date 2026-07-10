> **DESIGN §6.1–6.4** · [↑ DESIGN index](../../DESIGN.md) · prev: [routing](routing.md) · next: [observability](observability.md)

# Kubernetes Deployment & Performance Engineering

**Target: millions of token verifications/sec, single-digit-ms, low cost.**

### 6.1 Why it's cheap: stateless verification

- Access/ID tokens are **asymmetric-signed JWTs**. Verification = fetch JWKS **once**, cache it, then do **signature checks in-memory**. **No DB, no Redis, no network** per verification.
- JWKS + discovery are **static-ish and edge/CDN-cached** with long TTLs (keyed by `kid`; rotate keys with overlap).
- Resource servers verify tokens **themselves** using our public keys — much of the verification load never even hits us.

### 6.2 Per-region cluster topology

- **`auth-hot` Deployment**: stateless, aggressively **HPA**-scaled on RPS/CPU, thin, in-proc LRU cache of JWKS + client metadata + revocation bloom filter. Runs many cheap replicas.
- **`management` Deployment**: dashboard/BFF, enrollment, consent, audit — modest scale, stickier, DB-heavy.
- **Postgres**: primary + read replicas; hot reads (client lookups, grants) served from replicas + Redis.
- **Redis**: short-TTL caches (auth codes, client config, rate-limit counters, session lookups), not on the JWT-verify path.
- **Internal transport**: **gRPC** between services; **REST/OIDC** at the protocol edge.

### 6.3 Emergency revocation without killing performance

- Short token TTLs (5–15 min) bound exposure.
- A compact, **edge-replicated revocation bloom filter** (token id / session id) lets us kill compromised tokens fast without a per-request DB lookup. False positives fall back to introspection (rare).

### 6.4 Observability & abuse-prevention WITHOUT tracking

- Metrics are **aggregate & non-identifying** (RPS, latency, error rates per region/RP — never per-user profiles).
- **Rate limiting / brute-force**: keyed on transient signals (IP hash + short window, RP, credential id) with short-lived counters in Redis, **not** durable per-user behavioral logs.
- **Anomaly detection**: velocity/geo-impossibility checks on ephemeral data only; nothing retained beyond the security window.
