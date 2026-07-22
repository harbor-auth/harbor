# observability-metrics

Give operators real visibility — request/error rates, latency, issuance and
verification volume, revocation and rate-limit activity — **without** the
high-cardinality per-user labels Harbor's privacy model forbids (§5, §11.2).
Adds a single privacy-safe metrics facade to `internal/telemetry/`: `Counter`,
`Histogram`, and `Gauge` helpers whose labels are drawn from a **compile-time
allow-list** of low-cardinality, non-PII dimensions (`region`, `endpoint`,
`outcome`, `grant_type`, `error_code`, and `client_id` only where it is not
user-linked). There is **no** free-form label API, so a `user_id`, email, PPID,
or IP label is not even expressible. Metrics carry a `region` dimension for
per-region aggregates and never cross-region-join user data. An `internal/arch`
test CI-enforces that no metric label is sourced from a PII field. This is a
Wave-5 platform guardrail that lands first so every later feature meters through
the safe seam.
