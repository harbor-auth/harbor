# Tasks: Increase test coverage

## Prerequisites

- [x] None (existing test infrastructure is sufficient).

## Implementation

- [x] Add WebAuthn handler error path tests (FinishRegistration, FinishLogin).
- [x] Add WebAuthn service error path tests (FinishLogin).
- [x] Add OIDC Service.Authorize tests (validation errors, session failures).
- [x] Add OIDC Service.Token tests (Peek/Consume errors, issuance failures).
- [x] Add OIDC signalCodeReuse error logging tests.
- [x] Add OIDC resolver error path tests (FindGrant, CreateGrant, secret loader).
- [x] Add OIDC jwt_issuer error path tests (signer failures).
- [x] Add crypto envelope corrupted ciphertext tests (GCM tag, truncation).
- [x] Add clients grants edge case tests (DB errors, invalid UUIDs).
- [x] Add identity enroll error path tests (WrapDEK, Encrypt failures).
- [x] Add httpserver graceful shutdown tests.

## Tests

- [x] All new tests pass: `go test ./internal/...`
- [x] Coverage verification: all non-generated packages ≥80%.

## Validation

- [x] `go test ./internal/... -cover` — all packages pass with ≥80% coverage.
- [x] Coverage report created: `docs/coverage-report.md`.
- [x] OpenSpec artifacts created and validated.
