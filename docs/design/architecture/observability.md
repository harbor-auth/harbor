> **DESIGN §6.5** · [↑ DESIGN index](../../DESIGN.md) · prev: [performance](performance.md)

# Observability, SLOs & Privacy Invariants

This extends §6.4: it specifies *how* we observe the system while keeping the **no-tracking promise (§2.1–§2.2)** intact. The guiding rule is simple — **observability tells us how the *system* is doing, never what a *user* is doing.** Every telemetry signal is aggregate, PII-free, and region-scoped.

#### 6.5.1 Aggregate-only metrics

- Metrics are **counters/histograms with low-cardinality labels only**: `region`, `endpoint`, coarse `client_id`, `status`, `factor_type`. **Never** per-user labels — no `user_id`, no `email`, no `IP`, no PPID as a label. (`client_id` is **RP-level, not user, data** and is kept coarse enough to avoid RP-behavior profiling, so it stays "aggregate & non-identifying" per §2.2.)
- **The cardinality trap is also the privacy trap:** a user-identifying label would both explode metric cardinality (cost/perf) **and** violate the no-tracking promise. So it's **forbidden by construction**, not merely discouraged — the two failure modes reinforce each other, which is convenient.
- **RED** on the hot path (§6.1) — **R**ate, **E**rrors, **D**uration per endpoint/region; **USE** (Utilization/Saturation/Errors) for resources. Prometheus-style pull, aggregated at the regional collector.
- Consistent with §2.2, the **hot path emits only aggregate, non-identifying metrics** — no per-user analytics, ever.

#### 6.5.2 Tracing without PII

- **OpenTelemetry** distributed tracing for latency analysis and debugging — but spans carry **zero PII**: no user id, email, token contents, PPID, or relay address.
- Correlation is via **opaque request/correlation ids** that are **not linkable to a user** and are not persisted against user records.
- **Span attributes are deny-by-default allow-listed** (a scrubbing processor drops anything not explicitly permitted), so PII can't leak into a span even by accident.
- **Tail-based sampling** keeps tracing cheap on the millions/sec path (sample the interesting tails — errors, slow spans — not every request). Traces are **short-retention**.

#### 6.5.3 Structured logging (not the audit log)

- **Structured JSON logs at boundaries only** — log the **event *type*** and **coarse outcome** (e.g. `token_issue`, `ok`/`denied`), **not the subject**. **No request bodies, tokens, secrets, or PII.** Redaction is enforced via **deny-by-default field allow-listing**.
- **These are operational logs, not the user-facing audit log.** The **audit log** (§4.3, §11.6) is a *separate*, **user-owned**, per-region record the user can see and export; operational logs hold **no behavioral profile** and are not a shadow audit trail. Keeping them distinct is deliberate — operational logs are ephemeral diagnostics; the audit log is a durable, user-visible artifact.

#### 6.5.4 Per-region dashboards & telemetry residency

**Telemetry itself is region-scoped** — this is a first-class sovereignty property, not an afterthought:

- Metrics, traces, and logs are **collected and stored in the same jurisdiction** as the data plane they observe (§5). Raw per-user or region-local telemetry **never** flows into a global stack.
- A **global view** is built **only** from **aggregate, non-identifying rollups** (e.g. "EU hot-path p99 = 3ms, error rate = 0.01%") — no raw events, no cross-region PII.
- **Per-region dashboards** cover: the **hot path** (RPS, p50/p95/p99, error rate, saturation), the **cold path** (dashboard/mgmt latency & errors), and **dependencies** (Postgres, Redis, KMS/HSM health).

#### 6.5.5 SLOs & error budgets

We define explicit SLOs and let **error budgets drive release policy** (§1.8): when a service burns its budget, **feature deploys freeze** and effort shifts to reliability until the budget recovers.

| Service | SLI | SLO target | Notes |
|---|---|---|---|
| Hot path — token verify/issue | Successful, in-budget responses | **99.99%** availability | Statelessness (§6.1) makes this achievable cheaply. |
| Hot path — latency | Requests under the p99 budget | **p99 ≤ single-digit ms** | Offline JWKS verify keeps this flat under load (§6.1). |
| Cold path — dashboard/mgmt | Successful responses | **99.9%** availability | Looser; not on the auth critical path. |
| OIDC discovery / JWKS | Availability of `/.well-known/*`, `/jwks.json` | **99.99%** | Edge/CDN-cached (§6.1), so effectively static. |
| Refresh / revocation | Successful refresh & revoke ops | **99.95%** | DB-backed (§3.5); regional. |

**Alerting on budget burn** uses **multi-window, multi-burn-rate** logic: a **fast burn** (budget being consumed quickly) **pages**; a **slow burn** opens a **ticket**. This avoids both alert fatigue and silent slow degradation.

#### 6.5.6 Alerting

- **Alert on symptoms / SLO burn** (user-facing: error rate, latency, availability), **not** on noisy causes. **Page on fast burn, ticket on slow burn** (per §6.5.5).
- **Security-relevant alerts** fire on **aggregate** signals only — never per-user tracking: spikes in **auth failures**, **PKCE/nonce/state** validation failures (§11.7), **revocation-bloom** lookup rates, and **key-rotation** events (§7.3).
- **All alerts are per-region**, so an incident is attributed to and handled within its jurisdiction (§5).

#### 6.5.7 Privacy invariants for observability (non-negotiable)

- **No PII in metrics labels, trace spans, or logs** — ever (no user id/email/IP/PPID/relay/token).
- **Deny-by-default attribute allow-listing** for spans and log fields; redaction enforced in the pipeline.
- **Telemetry is region-scoped**; only aggregate, non-identifying rollups leave a region.
- **Short retention** for metrics/traces/logs; **no third-party analytics or SDKs** in any surface (§2.2, §9).
- **Ephemeral abuse-detection signals only** (§6.4) — nothing retained beyond the security window.
- **Operational logs ≠ audit log** (§4.3, §11.6): the audit trail is the *only* user-linked record, and it's user-owned.
