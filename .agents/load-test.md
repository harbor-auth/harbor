---
name: load-test
description: Hot-path throughput & p99 latency load tests as a pre-release gate (§1.8 stage 8, §6.5.5 SLOs).
---

Run Harbor's hot-path load tests. Per `docs/DESIGN.md` §1.8 **Stage 8**, load tests run **pre-release** against explicit **throughput & p99 budgets** — **failing the budget blocks the release**. The hot path is designed for **millions of stateless token verifications/sec at single-digit-ms p99** (§6.1/§6.5.5).

> **Update this skill:** if the load tool, scenarios, endpoints, or SLO thresholds below drift from the code/design, fix this file as part of your change. Harbor is greenfield — this describes the **intended** workflow per the design and is updated as the code lands. A stale skill is a bug.

## The budgets (§6.5.5) — the pass/fail thresholds

Encode the SLOs as the thresholds the test **fails on**:

| Metric | Budget (fail if breached) |
|---|---|
| **p99 latency** on `/verify`, `/token` | **single-digit ms** (target p99 < 10ms, ideally < 5ms) |
| **Success rate under load** | **≥ 99.99%** (error rate < 0.0001) |
| **Sustained throughput** | target RPS met with **no error-rate regression** |

## Endpoints to exercise

- **`/verify`** — offline JWKS token verify; **highest-volume**, must stay **flat under load**.
- **`/token`** — issuance / code exchange.
- **`/authorize`** — code exchange.
- **`/.well-known/openid-configuration`** + **`/jwks.json`** — edge-cached, should be trivially fast.

## Tooling

Prefer **k6** (scriptable, first-class `thresholds` that encode the SLO and **exit non-zero** when breached). `vegeta`/`wrk` are fine for simple constant-rate checks.

```js
// loadtest/verify.js — thresholds ARE the SLO (§6.5.5)
export const options = {
  scenarios: {
    verify: { executor: 'constant-arrival-rate', rate: 50000, timeUnit: '1s',
              duration: '2m', preAllocatedVUs: 500, maxVUs: 2000 },
  },
  thresholds: {
    http_req_duration: ['p(99)<10'],   // single-digit-ms p99 budget
    http_req_failed:   ['rate<0.0001'], // 99.99% success
  },
}
```

## Method

1. **Warm the in-process caches** (JWKS, revocation bloom filter) before measuring.
2. Run a **constant-arrival-rate** scenario at/above target RPS for a **sustained** window.
3. Measure **p99/p999** and **error rate**; compare against budget.
4. Test the **stateless** hot path in isolation — **`/verify` shouldn't touch the DB**. If p99 rises with load, that's a regression to investigate.
5. Run against a **production-like build** (§1.8 Stage 4 image), **not a dev binary**.

## How to run (intended)

A `make load-test` / `task load-test` wrapper boots the prod-like `harbor-hot`, seeds a signing key + sample tokens, runs the k6 scripts with thresholds, and **fails the release on any breached threshold**.

```bash
make run-harbor-hot-prodlike        # Stage-4 image, not a dev binary
make seed-loadtest-keys-tokens      # signing key + sample tokens for /verify
k6 run loadtest/verify.js           # non-zero exit if a threshold is breached
k6 run loadtest/token.js
```

## CI placement (§1.8 Stage 8)

**Pre-release gate, after conformance (Stage 7).** Track **p99/throughput over time** to catch slow regressions (tie to §6.5 observability).

## On failure

A breached budget **blocks release**. Root-cause the regression — lock contention, allocation in the hot path, a cache miss, or accidental **DB/network I/O on `/verify`** — **don't just bump the threshold**.

## Checklist

- [ ] Run against a **prod-like build** (Stage-4 image), not a dev binary?
- [ ] **Caches warmed** (JWKS, revocation bloom filter) before measuring?
- [ ] **Constant-arrival-rate** at/above target RPS for a sustained window?
- [ ] Thresholds encode the SLO: **p99 < single-digit ms**, **error rate < 0.0001**?
- [ ] **`/verify` does no DB I/O** — p99 stays flat under load?
- [ ] Test **exits non-zero** on any breached budget (blocks release)?
- [ ] **p99/throughput tracked over time** for slow-regression detection (§6.5)?
