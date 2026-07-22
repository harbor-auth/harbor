# Tasks: Add grant_id foreign key to sessions table

## Prerequisites

- [x] `client-grant-persistence` (grants table must exist).
- [x] `session-ppid-seam` (session resolver populates grants).

## Implementation

- [x] Add migration `db/migrations/0006_grant_id_fk.up.sql` with `grant_id UUID` FK column.
- [x] Add rollback migration `db/migrations/0006_grant_id_fk.down.sql`.
- [x] Update `db/queries/sessions.sql` with `grant_id` in queries.
- [x] Run `make codegen` (sqlc generate).
- [x] Update `buildCreateSessionParams` to populate `grant_id` from `RefreshSession.GrantID`.
- [x] Extend `sessionQuerier` interface with `RevokeSessionsByGrant`.
- [x] Implement `DBSessionStore.RevokeSessionsByGrant`.
- [x] Update `rowToRefreshSession` to map `grant_id`.
- [x] Add `RevokeSessionsByGrant` to `oidc.SessionStore` interface.
- [x] Implement `InMemorySessionStore.RevokeSessionsByGrant`.
- [x] Update `noopSessionStore` with `RevokeSessionsByGrant` stub.
- [x] Update `issueRefreshToken` to populate `GrantID` from grant.
- [x] Remove `TODO(grant-fk)` comment from `Refresh` in `service.go`.

## Tests

- [x] Unit tests for `grant_id` in `sessions_test.go`:
  - CreateSession stores grant_id correctly.
  - RevokeSessionsByGrant only revokes matching grant_id sessions.
  - RevokeSessionsByUserClient revokes all sessions regardless of grant_id.
- [x] Refresh flow tests for GrantID propagation:
  - issueRefreshToken sets GrantID from grant.ID.
  - Refresh() rotation copies GrantID to new session.

## Validation

- [x] `go build ./... && go vet ./... && go test ./...`
- [x] `make agent-check` (golangci-lint version mismatch is tooling issue, not code)
- [x] `openspec validate grant-id-fk --strict`
