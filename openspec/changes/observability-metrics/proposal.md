# Proposal: Aggregate-only observability metrics (zero-PII)

## Problem

Harbor needs operational visibility (§6.1) but its privacy model (§5, §11.2)
forbids the usual observability shortcut — high-cardinality, per-user labels. A
single `user_id`, email, PPID, or IP label silently recreates the
behavioural-tracking capability Harbor denies (and blows up cardinality). Today
`internal/telemetry/` has no enforced contract that metrics are aggregate-only
and PII-free, and every Wave-5 feature wants to meter something — each one label
away from a privacy regression.

## Proposed Solution

1. **Bounded, allow-listed labels** — metric constructors accept labels only
   from a compile-time allow-list of low-cardinality, non-PII dimensions
   (`region`, `endpoint`, `outcome`, `grant_type`, `error_code`, non-user-linked
   `client_id`). No API accepts a free-form label value, so a PII label is not
   expressible.
2. **Counters + histograms + gauges, aggregate by construction** — no per-event
   unique identifier is retained.
3. **Region dimension** — a `region` label (from
   `regional-data-residency-routing`) gives per-region aggregates with no
   per-user breakdown.
4. **Instrumentation through the facade** — hot path (issuance, verification,
   introspection, `429`s), revocation activity, and Wave-5 feature events (relay
   accept/bounce, export/erase counts, cross-region-guard rejections).
5. **Enforcement test** — an `internal/arch` test asserts no metric label is
   drawn from a PII field, so the invariant is CI-checked.

## Non-Goals

- Per-user, per-session, or per-token metrics of any kind — forbidden by §5.
- A per-IP time series (even for abuse) — only aggregate `429` counts by
  `endpoint`/`region`.
- Log or trace PII — the same allow-list governs any future span attributes.
- Choosing a specific backend (Prometheus vs OTEL) — the facade abstracts it so
  the privacy contract holds regardless.

## Success Criteria

- [ ] A single metrics facade (`Counter`/`Histogram`/`Gauge`) is the only way to emit metrics.
- [ ] Labels are drawn from a compile-time allow-list of non-PII dimensions; there is no free-form label API.
- [ ] A `user_id`/email/PPID/IP label is **not expressible** through the facade.
- [ ] A `region` dimension provides per-region aggregates; metrics never cross-region-join user data.
- [ ] Hot-path and Wave-5 feature events are instrumented through the facade.
- [ ] An `internal/arch` test asserts no metric label is sourced from a PII field.
- [ ] Cardinality stays bounded (no unbounded label value).
- [ ] `make agent-check` clean.
