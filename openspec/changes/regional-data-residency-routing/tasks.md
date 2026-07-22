# Tasks: Regional data-residency routing (region-pinned, fail-closed)

## Prerequisites

- [ ] A **root** — no unbuilt prerequisites. Reuses the shipped
  `internal/region/` seam and the region-prefixed issuer already emitted by
  `real-token-issuance`. This is a Wave-5 platform guardrail that lands first
  (with `observability-metrics`) so later user-data features inherit it.
- [ ] **No DB migration.** Region is a request-scoped property + an existing
  datastore attribute; this change adds no table and reserves no migration
  prefix.

## Implementation

- [ ] `internal/region/resolve.go`: total host/issuer → region resolver; an
  unrecognised host returns an error (never a default region). Validate the
  host→region map at startup (refuse to boot on an empty/ambiguous map).
- [ ] `internal/region/context.go`: `WithRegion(ctx, region)` /
  `FromContext(ctx) (Region, error)`; `FromContext` fails closed when unset.
- [ ] Bind datastore/handle selection to the pinned region so a handler cannot
  reach another region's store.
- [ ] `internal/oidcapi/region_middleware.go`: resolve region from host, place
  it on the context, and assert region coherence before any user-data read.
- [ ] `internal/mgmtapi/region_middleware.go`: same guard on the cold-path
  user-data endpoints.
- [ ] Cross-region PII guard: on a region mismatch return a defined error, meter
  it (aggregate-only, no PII), and return no partial data.
- [ ] Issuer/host coherence: ensure `iss`, userinfo, and introspect hosts are
  region-coherent with the resolving host.
- [ ] Wire the region middleware in `cmd/harbor-hot/main.go` (and mgmt) ahead of
  user-data handlers.

## Tests

- [ ] A known region-prefixed host resolves to the correct region.
- [ ] An unknown host is rejected (not defaulted to any region).
- [ ] `FromContext` fails closed when the region is unset.
- [ ] A handler reading a user from a foreign region fails closed — a defined
  error, no partial data — and the mismatch is metered.
- [ ] Issuer/host region coherence holds for token issuance, userinfo, and
  introspection.
- [ ] Privacy: no cross-region datastore access is reachable from a
  region-pinned request.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate regional-data-residency-routing --strict`
