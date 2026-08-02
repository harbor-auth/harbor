# Add failing tests for required service collaborators

1. Identify the security-critical collaborators currently defaulted to no-op or
   deferred to runtime 501/503 responses in OIDC, management, WebAuthn, and the
   dashboard.
2. Add constructor-focused negative tests in the four assigned test files,
   preserving explicitly optional dependencies such as loggers and relay.
3. Run the focused packages and confirm the new tests fail for the intended
   missing-dependency behavior, then commit and push the test-first checkpoint.

## Task 2: composition-root startup contracts

1. Isolate each binary's startup function in tests and identify its HTTP listen
   boundary.
2. Require PostgreSQL, Redis, external URLs, registration authorization, and
   the shared user-DEK KEK to be rejected before that boundary.
3. Run the focused command tests and preserve the expected red state for the
   later production-wiring tasks.

## Task 3: OIDC test-only scaffold fixtures

1. Inventory production OIDC scaffolds and same-package/cross-package consumers.
2. Move package-local fixtures into `internal/oidc/test_stores_test.go`.
3. Add reusable fixtures under `internal/testsupport/oidc` and migrate external tests.
4. Run focused tests and production-package build checks.
