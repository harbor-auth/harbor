# Proposal: Regional data-residency routing (region-pinned, fail-closed)

## Problem

**Strict data residency** (§5) — a user's PII lives in their home region and
**never** leaves it — is a stated Harbor promise with no enforced seam. The
`internal/region/` helper exists but nothing (a) authoritatively resolves the
region for an inbound request, (b) pins the request to a single regional
datastore, or (c) fails closed when a handler would read a user across a region
boundary. Without this guardrail, every Wave-5 feature that touches user data
(email relay, compliance export, the consent dashboard) would re-implement
residency enforcement, and one missed check would silently leak PII across a
jurisdiction.

## Proposed Solution

1. **Total region resolution** — resolve the active region from the request
   host / issuer prefix (`https://eu.harbor.id` → `eu`). Resolution is total:
   an unrecognised host resolves to **no** region and the request is rejected,
   never defaulted.
2. **Request-scoped region context** — carry the resolved region on the
   `context.Context` and bind datastore selection to it, so a handler cannot
   physically reach another region's store; `region.FromContext` fails closed
   when the region is unset.
3. **Cross-region PII guard** — middleware asserts the region a handler is about
   to read a user from equals the request's pinned region; a mismatch returns a
   defined error and is metered (aggregate-only), never partial data.
4. **Issuer/host coherence** — `iss`, userinfo, and introspect hosts are
   region-coherent with the resolving host, so a token minted in one region is
   only verified/introspected on that region's surface.

## Non-Goals

- Cross-region replication, failover, or migration of user data — residency is
  strict; a user's data does not move.
- Region **selection** at enrollment (which region a new user lands in) — that
  is an enrollment concern; this change enforces residency for existing rows.
- Operator/aggregate control-plane endpoints reading user PII cross-region —
  they read only aggregate, no-PII data (see `observability-metrics`).
- A new table — region is a request-scoped property and an existing datastore
  attribute, not new persisted state.

## Success Criteria

- [ ] A known region-prefixed host resolves to exactly one region; an unknown host is **rejected**, never defaulted.
- [ ] The resolved region is request-scoped; `region.FromContext` fails closed when unset.
- [ ] Datastore selection is bound to the pinned region — a handler cannot reach another region's store.
- [ ] A cross-region user read returns a defined error, is metered (aggregate-only), and returns **no** partial data.
- [ ] `iss`, userinfo, and introspect hosts are region-coherent with the resolving host.
- [ ] No cross-region datastore access is reachable from a region-pinned request.
- [ ] `make agent-check` clean.
