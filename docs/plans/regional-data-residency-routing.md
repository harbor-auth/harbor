---
title: Regional data-residency routing (region-pinned issuers & no cross-region PII)
status: draft
design_refs: [§5, §4, §11.2]
targets: [internal/region/, internal/oidcapi/, internal/mgmtapi/, cmd/harbor-hot/]
promoted_to: null
openspec: changes/regional-data-residency-routing
created: 2026-07-22
---

# Regional data-residency routing (plan)

> **Dependency order:** a **root** for Wave 5 (no unbuilt prerequisites). This is
> a **platform guardrail** that every later Wave-5 feature is constrained by, so
> it lands **first** (alongside `observability-metrics`). It reuses the shipped
> `internal/region/` seam and adds region resolution + a cross-region-PII guard
> to the request path; it introduces no new table and does not touch the token
> crypto. Build it before `email-relay-service`, `compliance-export`, and
> `consent-management-ui`, all of which must inherit the region-pinning
> invariant.

## Problem

Harbor promises **strict data residency** (§5): a user's PII lives in their home
region and **never** leaves it — not via a token, not via a cross-region DB
lookup, not via an issuer that resolves a user from the wrong region. Today the
region concept exists only as a thin `internal/region/` helper; there is no
enforced seam that (a) resolves the region for an inbound request from its host /
issuer prefix, (b) pins each request to a **single** regional datastore, and
(c) **fails closed** when a handler would read a user's PII across a region
boundary. Without this guardrail, every subsequent feature that touches user
data (email relay, compliance export, the consent dashboard) would each have to
re-implement residency enforcement, and a single missed check would silently
leak PII across a jurisdiction boundary.

## Proposed approach

Make region a **first-class, request-scoped, fail-closed** property.

1. **Region resolution (`internal/region/`)** — resolve the active region from
   the request host / issuer prefix (e.g. `https://eu.harbor.id` →
   `region=eu`). The issuer is already region-prefixed; this makes the mapping
   authoritative and one-way. Resolution is **total**: an unrecognised host
   resolves to no region and the request is rejected, never defaulted.
2. **Request-scoped region context** — carry the resolved region on the request
   `context.Context` and bind datastore selection to it, so a handler physically
   cannot reach another region's store. A helper `region.FromContext(ctx)`
   returns the pinned region (or an error → fail closed).
3. **Cross-region PII guard (`internal/oidcapi/`, `internal/mgmtapi/`)** —
   middleware asserts that the region a handler is about to read a user from
   matches the request's pinned region; a mismatch returns a defined error and
   is metered (via `observability-metrics`, aggregate-only) — it **never**
   returns partial data.
4. **Issuer/host coherence** — the issued token's `iss` and any `userinfo` /
   `introspect` host MUST be region-coherent with the resolving host, so a token
   minted in `eu` is only ever verified/introspected on the `eu` issuer surface.
5. **`home_region` source of truth (decided)** — a user's authoritative
   `home_region` lives **only** in that user's home-region datastore (the
   per-region user row); there is **no** global user directory. The guard
   derives the request's region from the host/issuer prefix (item 1) and asserts
   it matches the region of the store it is about to read — it **never** performs
   a global `user_id → region` lookup to *discover* a user's region (that lookup
   would itself be the cross-region PII access we forbid, making the guard
   theater). Building such a global directory is a **non-goal**; if one is ever
   introduced it MUST be **PII-free** (opaque `user_id` → region code only — no
   email, name, or subject) and treated as non-PII routing metadata. See
   OpenSpec Decision 5 / REQ-005 for the normative statement.

## DESIGN alignment

Realises §5 (regional boundaries — PII pinned to home region, no cross-region
replication or lookup) and reinforces §4 (the hot path stays regional and
stateless — region resolution is a cheap host-prefix lookup, no DB round-trip)
and §11.2 (data-subject data stays in-region). Does **not** change `DESIGN.md` —
§5 already mandates residency; this plan builds the missing enforcement seam.

## Target code paths

- `internal/region/resolve.go` — host/issuer → region resolution (total; unknown
  host → error).
- `internal/region/context.go` — request-scoped region context
  (`WithRegion` / `FromContext`, fail-closed).
- `internal/oidcapi/region_middleware.go` — hot-path region-pinning + cross-region
  guard middleware.
- `internal/mgmtapi/region_middleware.go` — cold-path region-pinning for
  user-data endpoints.
- `cmd/harbor-hot/main.go` — wire the region middleware ahead of user-data
  handlers.

## Implementation checklist

- [ ] Total host/issuer → region resolver in `internal/region/` (unknown host → error, never a default region).
- [ ] Request-scoped region context (`WithRegion`/`FromContext`); `FromContext` fails closed when unset.
- [ ] Bind datastore/handle selection to the pinned region so a handler cannot reach another region's store.
- [ ] Cross-region PII guard middleware (`internal/oidcapi/`, `internal/mgmtapi/`): region mismatch → defined error, metered, never partial data.
- [ ] Issuer/host coherence: `iss`, userinfo, and introspect hosts are region-coherent with the resolving host.
- [ ] `home_region` stays per-region authoritative: the guard resolves region from the host/issuer prefix and does **no** global `user_id → region` lookup on the guard path (no global user directory is built).
- [ ] Wire region middleware in `cmd/harbor-hot/main.go` (and mgmt) ahead of user-data handlers.
- [ ] Tests: known host resolves to the right region; unknown host is rejected (not defaulted); a handler reading a user from a foreign region fails closed with no data returned; issuer/host region coherence holds.
- [ ] Tests (privacy): no cross-region datastore access is reachable from a region-pinned request; the guard path performs no global `user_id → region` directory lookup.
- [ ] Author & verify paired OpenSpec change: `openspec validate regional-data-residency-routing --strict`
- [ ] Reconcile & promote: `@plan promote regional-data-residency-routing`

## Risks & open questions

- **Fail-closed vs availability** — a mis-configured host map would reject real
  traffic. Mitigate with an explicit, tested host→region table and a loud
  startup validation (refuse to boot with an empty/ambiguous map) rather than a
  silent runtime default.
- **Region source of truth** — host-prefix is the chosen signal for the *request*
  region; a user's authoritative `home_region` is per-region-store-only, and the
  guard never does a global user lookup to find it (decided — see Proposed
  approach item 5). If an edge/LB rewrites Host, the trusted forwarded-host
  chain must be used (coordinate with ingress). A spoofable Host header must
  never select a region.
- **Multi-region operator endpoints** — operator/aggregate surfaces are
  control-plane and must be explicitly exempt from the user-PII guard while
  still never reading user PII cross-region (they read only aggregate,
  no-PII data — see `observability-metrics`).

## Definition of done

`go build/vet/test ./...` green; every user-data request is pinned to a single
resolved region; an unknown host is rejected rather than defaulted; a handler
cannot read a user's PII from another region (fails closed, metered, no partial
data); issuer/host are region-coherent; `make agent-check` clean. Ready to
`@plan promote`.
