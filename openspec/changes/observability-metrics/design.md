# Design: Aggregate-only observability metrics (zero-PII)

## Key Decisions

### Decision 1: A compile-time label allow-list — PII labels are unexpressible
**Chosen:** Metric helpers accept labels only from a compile-time allow-list of
low-cardinality, non-PII dimensions; there is no API that accepts a free-form
label value.
**Rationale:** Making the unsafe path unexpressible (rather than merely
discouraged) is the only durable defence. A reviewer can miss a stray
`user_id` label; a type system cannot. This turns "don't add PII labels" from a
convention into a compile-time guarantee.
**Alternatives considered:** A runtime denylist of known-PII keys (rejected —
fails open on any key not on the list); code-review discipline (rejected — one
miss is a permanent privacy regression); free-form labels + a scrubber (rejected
— scrubbing PII after the fact is unreliable and cardinality still explodes).

### Decision 2: Aggregate-only — counters/histograms/gauges, no per-event id
**Chosen:** Expose only aggregate instruments; never retain a per-event unique
identifier.
**Rationale:** Aggregates answer every operational question (rates, latencies,
error ratios) without a per-user or per-token series. No per-event id means no
accidental re-identification vector.
**Alternatives considered:** Per-request event logs with ids (rejected —
re-identifiable, violates §5); sampled per-user traces (rejected — a sample is
still per-user PII).

### Decision 3: Region is a first-class aggregate dimension
**Chosen:** Carry a `region` label (from the pinned request region) so operators
get per-region aggregates; metrics never cross-region-join user data.
**Rationale:** Operators legitimately need per-region health; region is
low-cardinality and non-PII. It gives useful breakdown without any per-user
dimension.
**Alternatives considered:** No region dimension (rejected — operators can't see
regional health); a `region`×`user` breakdown (rejected — reintroduces per-user
tracking).

### Decision 4: CI-enforced via an architecture test
**Chosen:** Extend `internal/arch/` to assert BOTH (a) no metric label is
sourced from a PII field AND (b) label-set cardinality bounds / small-n
suppression (Decision 5) are enforced — not just PII-field provenance.
**Rationale:** The allow-list makes PII labels unexpressible in the facade; the
arch test guards against a future bypass (e.g. someone adding a raw metrics
backend call) and against a quasi-identifier label whose cardinality resolves to
a single user. Defence in depth: type system + CI.
**Alternatives considered:** Rely on the type system alone (rejected — a raw
backend import could bypass the facade, and the type system cannot see that a
technically-non-PII label resolves to one user; the arch test catches both).

### Decision 5: Quasi-identifier labels get small-n suppression and bounded cardinality
**Chosen:** Even allow-listed labels can be quasi-identifiers: `client_id` for a
client with a single user makes every row effectively per-user, and a low-traffic
`region` crossed with a rare `error_code` can single out one event. `client_id`
is emitted ONLY for registered clients above a small-count floor (below the floor
it is bucketed/omitted); label-set cardinality is bounded, and rare combinations
are suppressed/bucketed rather than emitted at count 1.
**Rationale:** Invariant 3 (aggregate-only) is about *effect*, not just field
provenance — a technically-non-PII label that resolves to one user violates it
in spirit. Small-n suppression closes the quasi-identifier gap.
**Alternatives considered:** Emit `client_id` unconditionally (rejected —
single-user clients become per-user series); drop `client_id` entirely (rejected
— loses legitimate per-client operational insight above the floor).

## Interface sketch

```go
package telemetry

// Label is a phantom-typed, allow-listed dimension; there is no constructor for
// a free-form label value, so a PII label cannot be built.
type Label struct{ /* unexported; only allow-listed builders exist */ }

func Region(r region.Region) Label
func Endpoint(name string) Label   // name is an allow-listed route constant
func Outcome(o Outcome) Label      // enum: success | error | denied | limited

func NewCounter(name, help string, dims ...Dimension) *Counter
func (c *Counter) Inc(labels ...Label)
```

## Security & privacy invariants

- No metric label is sourced from a PII field (`user_id`, email, PPID, IP,
  subject) — enforced by the facade type and the `internal/arch` test.
- Only aggregate instruments exist; no per-event unique id is retained.
- Abuse metering exposes only aggregate `429` counts by `endpoint`/`region`,
  never a per-IP series.
- Quasi-identifier labels are small-n suppressed: `client_id` is emitted only
  above a small-count floor and rare `region`×`error_code` combinations are
  bucketed, so no label resolves to a single user (Decision 5).
