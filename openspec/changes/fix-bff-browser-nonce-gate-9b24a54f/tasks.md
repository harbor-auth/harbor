# fix-bff-browser-nonce-gate-9b24a54f — Tasks

## Tests

- [x] Cover an absent `BrowserNonceHash` at `BeginLogin`.
- [x] Cover an absent `BrowserNonceHash` at `FinishLoginWithParsedData`.
- [x] Cover an absent `BrowserNonceHash` at `GetAuthorizeComplete`.
- [x] Retain coverage for sessions created by `/authorize` with a matching
      nonce hash and cookie.

## Implementation

- [x] Make both BFF login gates reject an absent browser nonce hash.
- [x] Make authorization completion reject an absent browser nonce hash.
- [x] Preserve nonce-cookie parsing and constant-time comparison behavior.

## Validation

- [x] `gofmt` on changed Go files.
- [x] Targeted BFF and OIDC tests.
- [x] `go build ./...`.
- [x] `go vet ./...`.
- [x] `go test ./...`.
- [x] `make agent-check`.
- [x] `openspec validate fix-bff-browser-nonce-gate-9b24a54f --strict`.
