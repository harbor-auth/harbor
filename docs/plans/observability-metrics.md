---
title: Aggregate-only observability metrics (zero-PII counters & histograms)
status: draft
design_refs: [§6.5, §5, §11.2]
targets: [internal/telemetry/, internal/oidcapi/, internal/mgmtapi/]
promoted_to: null
openspec: changes/observability-metrics
created: 2026-07-22
---

# Aggregate-only observability metrics (plan)

> **Dependency order:** a **root** for Wave 5 (no unbuilt prerequisites). Lands
> **first**, alongside `regional-data-residency-routing`, because every later
> Wave-5 feature emits metrics (relay accept/bounce counters, export counts,
> cross-region-guard rejections) and they MUST all go through a **zero-PII,
> aggregate-only** metrics seam. Build it before the features that meter, so
> there is one privacy-safe metrics API and no per-user label ever leaks in.

## Problem

Harbor needs operational visibility — request rates, error rates, latency, token
issuance/verification volume, revocation activity — but its privacy model (§5,
§11.2) forbids the usual observability shortcut of high-cardinality, per-user
labels. A single `user_id`, email, PPID, `client_id`-plus-subject, or IP label
on a metric silently recreates the behavioural-tracking capability Harbor denies,
and cardinality explosions also destroy the metrics backend. Today there is a
thin `internal/telemetry/` package but **no enforced contract** that metrics are
aggregate-only and label sets are bounded and PII-free. Every later Wave-5
feature wants to meter something; without a guarded seam, each is one careless
label away from a privacy regression.

## Proposed approach

Provide a **single, privacy-safe metrics facade** in `internal/telemetry/` that
makes the safe path the only path.

1. **Bounded, allow-listed labels** — metric constructors accept labels only
   from a **compile-time allow-list of low-cardinality, non-PII dimensions**
   (e.g. `region`, `endpoint`, `outcome`, `client_id` **only where it is not
   user-linked**, `grant_type`, `error_code`). There is **no** API that accepts
   an arbitrary/free-form label value, so a `user_id`/email/PPID/IP label is not
   expressible.
2. **Counters + histograms only, aggregate by construction** — expose
   `Counter`, `Histogram`, and `Gauge` helpers that increment/observe with the
   allow-listed label set; no per-event unique identifier is retained.
3. **Region dimension** — metrics carry a `region` label (from
   `regional-data-residency-routing`) so operators get per-region aggregates
   without any per-user breakdown. Metrics themselves never cross-region-join
   user data.
4. **Wiring at the meter sites** — instrument the hot path (issuance,
   verification, introspection, `429`s), revocation activity, and the Wave-5
   feature events (relay accept/bounce, export/erase counts, cross-region-guard
   rejections) — always through the facade.
5. **Enforcement test** — an architecture test (mirroring `internal/arch/`)
   asserts no metric label is drawn from a PII field, so the invariant is
   CI-checked, not just documented.

## DESIGN alignment

Realises §6.5 (operational visibility / observability) **without**
violating §5 and §11.2 (no per-user tracking, PII stays in-region and out of
telemetry). Does **not** change `DESIGN.md` — the design already forbids per-user
observability; this plan builds the seam that makes that forbidden state
unexpressible.

## Target code paths

- `internal/telemetry/metrics.go` — the privacy-safe facade (`Counter`,
  `Histogram`, `Gauge` with allow-listed label sets).
- `internal/telemetry/labels.go` — the compile-time allow-list of non-PII label
  dimensions.
- `internal/telemetry/metrics_test.go` — facade + label-allow-list tests.
- `internal/arch/arch_test.go` — extend the architecture test to assert no PII
  field feeds a metric label.
- `internal/oidcapi/`, `internal/mgmtapi/` — instrument meter sites through the
  facade.

## Implementation checklist

- [ ] `internal/telemetry/labels.go`: compile-time allow-list of low-cardinality, non-PII label dimensions (`region`, `endpoint`, `outcome`, `grant_type`, `error_code`, non-user-linked `client_id`).
- [ ] `internal/telemetry/metrics.go`: `Counter`/`Histogram`/`Gauge` helpers that accept **only** allow-listed labels — no free-form label API exists.
- [ ] Add the `region` dimension (from `regional-data-residency-routing`) for per-region aggregates.
- [ ] Instrument the hot path: issuance, verification, introspection, `429` rate-limits, revocation activity — via the facade.
- [ ] Provide meter hooks the Wave-5 features consume (relay accept/bounce, export/erase counts, cross-region-guard rejections) — all label-bounded.
- [ ] Extend `internal/arch/arch_test.go`: assert no metric label is sourced from a PII field (`user_id`, email, PPID, IP, subject).
- [ ] Tests: a counter/histogram increments with allow-listed labels; attempting a PII/free-form label does not compile / is not expressible; per-region aggregation works; cardinality stays bounded.
- [ ] Author & verify paired OpenSpec change: `openspec validate observability-metrics --strict`
- [ ] Reconcile & promote: `@plan promote observability-metrics`

## Risks & open questions

- **`client_id` cardinality & linkage** — `client_id` is low-cardinality and not
  user-PII, but a `client_id` + narrow time window could correlate to a single
  user for a rarely-used RP. Keep `client_id` labels only on
  client-scoped (not user-scoped) metrics; never combine `client_id` with any
  user dimension. Document this explicitly in `labels.go`.
- **IP for abuse metrics** — `rate-limiting` needs abuse visibility but IP is
  PII. Meter only **aggregate** `429` counts (by `endpoint`/`region`), never a
  per-IP time series.
- **Backend choice** — Prometheus-style pull vs OTEL push is an implementation
  detail; the facade must abstract it so the privacy contract holds regardless.
- **Exemplars/traces** — if tracing is added later, span attributes are subject
  to the same allow-list; do not let a trace attribute smuggle in a PII field.

## Definition of done

`go build/vet/test ./...` green; a single privacy-safe metrics facade is the
only way to emit metrics; label sets are compile-time bounded to non-PII
dimensions (a `user_id`/email/PPID/IP label is not expressible); an architecture
test CI-enforces the no-PII-label invariant; hot-path + Wave-5 feature events are
instrumented with per-region aggregates; `make agent-check` clean. Ready to
`@plan promote`.
