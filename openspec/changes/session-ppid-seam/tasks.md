# Tasks: Session seam — login → PPID → subject

## Prerequisites

- [ ] `user-enrollment` (real user with `pairwise_secret`).
- [ ] `client-grant-persistence` (RP `sector_id` + `GrantStore`).
- [ ] `real-token-issuance` (so the resolved PPID is signed into a real token).

## Implementation

- [ ] `internal/oidc/resolver.go`: real `SessionResolver` (login → decrypt secret → DerivePPID → find-or-create grant).
- [ ] Expose the authenticated `user_id` from the webauthn login path to the resolver.
- [ ] Scope-superset check to skip redundant consent.
- [ ] `cmd/harbor-hot/main.go`: wire the real resolver (replace `NewStubSessionResolver`); keep the stub for tests.

## Tests

- [ ] Same user + same RP ⇒ stable `sub`.
- [ ] Same user + different sector ⇒ different `sub` (unlinkability, §3.2).
- [ ] Consent recorded once; subset scope reuses grant; superset re-prompts.
- [ ] Rejection ⇒ `access_denied`.
- [ ] Fail-closed: decrypt/lookup errors deny; no token with a raw `user_id`.
- [ ] `pairwise_secret` never appears in logs or token claims.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate session-ppid-seam --strict`
