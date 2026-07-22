# Spec: Aggregate-only observability metrics (zero-PII)

Adds a single privacy-safe metrics facade whose labels are drawn from a
compile-time allow-list of non-PII dimensions, exposes only aggregate
instruments, carries a per-region dimension, and is CI-enforced by an
architecture test asserting no metric label is sourced from a PII field.
Realises §6.1 visibility without violating §5/§11.2.

## ADDED Requirements

### Requirement: REQ-001 Compile-time non-PII label allow-list

The system SHALL emit metrics only through a facade whose labels are drawn from
a compile-time allow-list of low-cardinality, non-PII dimensions (`region`,
`endpoint`, `outcome`, `grant_type`, `error_code`, non-user-linked `client_id`).
The facade MUST NOT expose any API that accepts a free-form label value, so a
`user_id`, email, PPID, or IP label is NOT expressible.

#### Scenario: Allow-listed label is accepted

**Given** a counter labelled by `endpoint` and `outcome`
**When** it is incremented for a request
**Then** the increment is recorded with those allow-listed labels

#### Scenario: A PII label is not expressible

**Given** the metrics facade
**When** a caller attempts to attach a `user_id` (or email/PPID/IP) label
**Then** there is no facade API to do so and the code does not compile

### Requirement: REQ-002 Aggregate-only instruments

The system SHALL expose only aggregate instruments (counters, histograms,
gauges) and MUST NOT retain any per-event unique identifier.

#### Scenario: No per-event identifier is retained

**Given** a metered request
**When** the metric is recorded
**Then** only an aggregate count/observation is retained — no per-event or per-user identifier

### Requirement: REQ-003 Per-region aggregation without user join

The system SHALL provide a `region` dimension for per-region aggregates and MUST
NOT cross-region-join user data in any metric.

#### Scenario: Per-region counters

**Given** requests served in regions `eu` and `us`
**When** a request counter is scraped
**Then** it reports per-region aggregates with no per-user breakdown

### Requirement: REQ-004 CI-enforced no-PII-label invariant

The system SHALL include an architecture test asserting that no metric label is
sourced from a PII field (`user_id`, email, PPID, IP, subject).

#### Scenario: Architecture test fails on a PII-sourced label

**Given** the architecture test suite
**When** a metric label would be sourced from a PII field
**Then** the architecture test fails
