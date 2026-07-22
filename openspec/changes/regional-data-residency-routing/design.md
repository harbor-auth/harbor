# Design: Regional data-residency routing (region-pinned, fail-closed)

## Key Decisions

### Decision 1: Region resolution is total — unknown host is rejected, never defaulted
**Chosen:** Resolve region from the request host / issuer prefix via an explicit,
startup-validated host→region map; an unrecognised host resolves to **no**
region and the request is rejected.
**Rationale:** A default region is a silent data-residency violation waiting to
happen — it would route a user's PII to the wrong jurisdiction. A total resolver
with no default makes residency failures loud and safe (rejected) rather than
quiet and unsafe (mis-routed).
**Alternatives considered:** Default to a "primary" region on an unknown host
(rejected — silently violates §5); infer region from the user row after lookup
(rejected — the lookup itself is the cross-region access we must prevent).

### Decision 2: Region is request-scoped and pins datastore selection
**Chosen:** Carry the resolved region on the `context.Context` and bind
datastore/handle selection to it; `region.FromContext` fails closed when unset.
**Rationale:** Making the datastore reachable only through the region-pinned
context turns residency into a structural property (a handler physically cannot
reach another region's store) rather than a discipline every handler must
remember.
**Alternatives considered:** A per-handler region argument (rejected — easy to
forget, not enforced); a global "current region" (rejected — unsafe under
concurrent multi-region serving).

### Decision 3: Cross-region guard fails closed with no partial data
**Chosen:** When a handler would read a user from a region other than the
pinned one, return a defined error, meter it (aggregate-only, no PII), and
return nothing.
**Rationale:** The whole point of residency is that cross-region PII access does
not happen; the guard must never leak even a partial record. Metering (without
PII) makes the event observable for operators without recreating the
cross-region leak in telemetry.
**Alternatives considered:** Best-effort filtering of foreign rows (rejected —
any returned byte is a leak); log the full offending record (rejected — that IS
the cross-region PII exposure, now in logs).

### Decision 4: Issuer/host coherence
**Chosen:** `iss`, userinfo, and introspect hosts are region-coherent with the
resolving host, so a token minted on the `eu` issuer is only ever
verified/introspected on the `eu` surface.
**Rationale:** Residency must hold across the token lifecycle, not just at read
time — a token that resolves a user on the wrong region's issuer is a
cross-region leak by another name.
**Alternatives considered:** Region-agnostic global issuer (rejected — breaks
residency for userinfo/introspection, which resolve the user).

## Interface sketch

```go
package region

// Resolve maps an inbound host (or issuer) to a region. It is total: an
// unrecognised host returns an error and MUST NOT default to any region.
func Resolve(host string) (Region, error)

// WithRegion pins a region onto the request context.
func WithRegion(ctx context.Context, r Region) context.Context

// FromContext returns the pinned region, failing closed (error) when unset.
func FromContext(ctx context.Context) (Region, error)
```

## Security & privacy invariants

- Unknown host → rejected, never defaulted (Decision 1).
- A region-pinned request cannot reach another region's datastore (Decision 2).
- A cross-region user read fails closed with no partial data; the event is
  metered without PII (Decision 3).
- Token `iss` / userinfo / introspect hosts are region-coherent (Decision 4).
