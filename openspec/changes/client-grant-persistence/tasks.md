# Tasks: Client & grant persistence

## Prerequisites

- [ ] None (the `grants` table + queries already exist; `relying_parties` added here).

## Implementation

- [ ] Add `SectorID string` to `oidc.Client` in `internal/oidc/store.go`; update all `registry.Put(...)` construction sites (currently `cmd/harbor-hot/main.go`).
- [ ] Confirm the `relying_parties` table exists (check `0001`/`0002`); add expand-only `0003` migration if missing.
- [ ] `db/queries/relying_parties.sql` (Get/List/Upsert); regenerate `internal/gen/db`.
- [ ] `internal/clients/registry.go`: sqlc-backed `ClientRegistry`; map row → `oidc.Client` (incl. `sector_id`).
- [ ] `internal/oidc/grants.go`: `GrantStore` interface + `Grant` type.
- [ ] `internal/clients/grants.go`: sqlc-backed `GrantStore` over `grants.sql`.
- [ ] `cmd/harbor-hot/main.go`: wire the DB-backed registry (keep in-memory for tests).

## Tests

- [ ] Unknown client ⇒ not found; known client resolves incl. `sector_id`.
- [ ] Exact redirect-URI match preserved (near-match rejected).
- [ ] Grant create → find → revoke; `ListGrantsByUser` excludes revoked.
- [ ] `region` populated on grant writes.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate client-grant-persistence --strict`
