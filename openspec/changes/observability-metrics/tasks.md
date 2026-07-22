# Tasks: Aggregate-only observability metrics (zero-PII)

## Prerequisites

- [ ] A **root** — no unbuilt prerequisites. Soft-pairs with
  `regional-data-residency-routing` for the `region` label. Lands first in
  Wave 5 so later features meter through the safe facade.
- [ ] **No DB migration.** Metrics are in-process aggregates; this change adds
  no table and reserves no migration prefix.

## Implementation

- [ ] `internal/telemetry/labels.go`: compile-time allow-list of low-cardinality,
  non-PII label dimensions (`region`, `endpoint`, `outcome`, `grant_type`,
  `error_code`, non-user-linked `client_id`). Document the `client_id`
  never-with-a-user-dimension rule inline.
- [ ] `internal/telemetry/metrics.go`: `Counter` / `Histogram` / `Gauge`
  helpers that accept **only** allow-listed labels — no free-form label API.
- [ ] Add the `region` dimension sourced from the pinned request region.
- [ ] Instrument the hot path via the facade: issuance, verification,
  introspection, `429` rate-limits, revocation activity.
- [ ] Provide label-bounded meter hooks for the Wave-5 features (relay
  accept/bounce, export/erase counts, cross-region-guard rejections).
- [ ] Extend `internal/arch/arch_test.go`: assert no metric label is sourced
  from a PII field (`user_id`, email, PPID, IP, subject).

## Tests

- [ ] A counter/histogram/gauge increments/observes with allow-listed labels.
- [ ] A PII or free-form label is not expressible (does not compile / is
  rejected by the facade type).
- [ ] Per-region aggregation works; metrics never join user data across regions.
- [ ] Cardinality stays bounded — no unbounded label value is accepted.
- [ ] Abuse metering exposes only aggregate `429` counts, never a per-IP series.
- [ ] Architecture test: no metric label is sourced from a PII field.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate observability-metrics --strict`
