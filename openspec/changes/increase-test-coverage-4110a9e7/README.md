# Increase test coverage

This change adds targeted error path and edge case tests across all internal
packages to achieve 80%+ test coverage.

## Summary

- Added error path tests for WebAuthn, OIDC, crypto, identity, and clients packages.
- All non-generated internal packages now exceed 80% coverage.
- Coverage report documented in `docs/coverage-report.md`.

## Files Changed

- `internal/webauthn/handlers_test.go` — FinishRegistration/FinishLogin error paths
- `internal/webauthn/service_test.go` — FinishLogin service error paths
- `internal/oidc/service_test.go` — Authorize/Token error paths, signalCodeReuse
- `internal/oidc/resolver_test.go` — PPIDSessionResolver error paths
- `internal/oidc/jwt_issuer_test.go` — signer failure paths
- `internal/crypto/envelope_test.go` — corrupted ciphertext tests
- `internal/clients/grants_test.go` — edge cases and error paths
- `internal/identity/enroll_test.go` — WrapDEK/Encrypt failure paths
- `docs/coverage-report.md` — coverage documentation
