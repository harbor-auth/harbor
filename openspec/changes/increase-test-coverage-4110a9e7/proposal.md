# Proposal: Increase test coverage

## Problem

Several internal packages have test coverage below the 80% target, leaving error
paths and edge cases untested. This increases risk of regressions and makes
refactoring more dangerous.

## Proposed Solution

- Add targeted error path tests for each package below 80% coverage.
- Add edge case tests for boundary conditions and failure modes.
- Document coverage results and justifications for any exclusions.
- Verify all non-generated packages reach 80%+ coverage.

## Non-Goals

- Testing generated code (`internal/gen/*`).
- Refactoring production code to improve testability.
- Adding integration or e2e tests (unit tests only).

## Success Criteria

- [x] All non-generated internal packages reach 80%+ coverage.
- [x] Error paths tested for WebAuthn, OIDC, crypto, identity, and clients.
- [x] Coverage report documented in `docs/coverage-report.md`.
- [x] `go test ./internal/... -cover` shows all packages ≥80%.
