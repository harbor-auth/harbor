# Tasks: Refresh token rotation (§3.5)

## Prerequisites

- [ ] `real-token-issuance` (refresh exchange mints fresh access/ID tokens).
- [ ] `session-ppid-seam` (sessions are bound to a real user<>RP identity).

## Implementation

- [ ] `internal/oidc/refresh.go`: refresh grant handling + rotation + reuse-detection; `SessionStore` interface.
- [ ] `internal/clients/sessions.go`: sqlc-backed `SessionStore` over `sessions.sql`.
- [ ] `api/openapi/harbor.yaml`: add `refresh_token` + `refresh_token_expires_in` to token response; add `grant_type=refresh_token` to token endpoint; regenerate `internal/gen/openapi`.
- [ ] `internal/oidc/token.go`: route `grant_type=refresh_token` to the new refresh handler.
- [ ] Issue refresh token on code exchange when `offline_access` is granted; new `sessions` row (region populated).
- [ ] `cmd/harbor-hot/main.go`: wire the session store.

## Tests

- [ ] Rotation returns a new token and invalidates the old (one-time use).
- [ ] Replaying the old token => theft signal + family revoke + `invalid_grant`.
- [ ] Expired/revoked session => `invalid_grant`.
- [ ] Hash-at-rest: no plaintext refresh token in the DB.
- [ ] Region populated on every `sessions` row.
- [ ] Atomic rotation: mid-rotation failure => no new token issued.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate refresh-token-rotation --strict`
