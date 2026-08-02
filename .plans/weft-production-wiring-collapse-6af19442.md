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

## Task 4: fail-closed OIDC service construction

1. Require every store, issuer/resolver, and revocation collaborator in
   `oidc.NewService`, returning a descriptive startup error for omissions.
2. Delete production noop session, grant, consent, revocation, outbox, and
   revoked-JTI implementations.
3. Migrate package and cross-package tests through test-only service fixtures.
4. Wire the durable consent store in the hot production graph and propagate
   constructor errors.
5. Run focused OIDC/API tests plus repository build and vet checks.

## Task 5: relocate BFF and rate-limiter memory scaffolds

1. Identify every production and test reference to the in-memory BFF session store and rate limiter.
2. Move test doubles behind test-only support, update tests to use the appropriate fixtures, and remove production fallbacks so Redis is the sole runtime implementation.
3. Run focused tests plus build/vet checks, review the diff, commit, rebase, and push the shared feature branch.
