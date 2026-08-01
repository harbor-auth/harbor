# fix-bff-browser-nonce-gate-9b24a54f — Tasks

## Regression tests

- [ ] Add focused BFF login tests proving `BeginLogin` and
      `FinishLoginWithParsedData` reject sessions with an absent
      `BrowserNonceHash` before security-sensitive downstream work.
- [ ] Add a focused OIDC API test proving `GetAuthorizeComplete` rejects an
      authenticated session with an absent `BrowserNonceHash` without redirect
      or code issuance, while retaining `/authorize`-created happy-path coverage.

## Implementation

- [ ] Invert the stored-hash condition at the gates in `internal/bff/login.go`
      so both login checkpoints fail closed on an absent hash and otherwise use
      the existing cookie reader and constant-time comparison.
- [ ] Invert the stored-hash condition in `internal/oidcapi/authorize.go` so
      authorization completion fails closed on an absent hash and otherwise
      preserves existing nonce comparison behavior.

## Validation and delivery

- [ ] Run gofmt, targeted BFF/OIDC tests, `go build ./...`, `go vet ./...`,
      `go test ./...`, and `make agent-check`.
- [ ] Run OpenSpec verification for this change.
- [ ] Create a pull request against `main`.
- [ ] After CI is green, squash-merge and verify GitHub reports the PR merged.
