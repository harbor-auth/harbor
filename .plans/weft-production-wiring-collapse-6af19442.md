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

## Task 6: relocate WebAuthn and enrollment memory scaffolds

1. Inventory package-local and cross-package consumers of the WebAuthn credential, ceremony, and enrollment-session memory stores.
2. Move same-package fixtures into `_test.go` files and expose only the enrollment fixture needed by command tests through `internal/testsupport`.
3. Remove management runtime fallbacks that reference the relocated fixtures, leaving durable DB/Redis implementations as the runtime choices.
4. Run focused tests plus build/vet checks, review the diff, commit, rebase, and push the shared feature branch.

## Task 7: collapse harbor-hot onto the durable graph

1. Make `run` reject missing PostgreSQL, Redis, login, issuer, and user-DEK key configuration before constructing the HTTP server.
2. Assemble clients, authorization codes, refresh sessions, grants, consents, BFF state, and revocation services exclusively from PostgreSQL and Redis.
3. Remove the development/demo graph, readiness guard, `HARBOR_DEV_MODE` branches, and obsolete signing bootstrap implementation and tests while retaining local crypto as the documented crypto-only exception.
4. Update focused startup and graph tests, then run command tests, repository build/vet, and the relevant project checks before committing and rebasing.

## Task 8: require management and WebAuthn constructor dependencies

1. Make management, WebAuthn service/handler, and dashboard constructors reject missing security-critical collaborators.
2. Preserve explicit optional audit, relay, logging, and product-toggle dependencies.
3. Migrate composition roots and test fixtures to the error-returning constructors.
4. Run focused tests, repository build/vet, and project checks before committing, rebasing, and pushing.

## Task 9: collapse harbor-mgmt onto the durable graph

1. Replace the production/development branch with one fail-closed `run` composition root that requires PostgreSQL, Redis, external URLs, registration authorization, and the shared user-DEK KEK.
2. Wire enrollment, WebAuthn, registration, consent/session management, recovery, MFA, compliance, audit, dashboard, and relay exclusively through DB/Redis-backed implementations.
3. Delete `runDevelopment`, its noop persister, conditional dependency branches, and development fallbacks while retaining the local key provider as the documented crypto exception.
4. Strengthen the composition-root tests, run focused and repository checks, then commit, rebase, and push the shared feature branch.

## Task 10: BYO-domain persistence schema

1. Amend the pre-launch relay migration with the durable BYO-domain lifecycle shape, global domain uniqueness, user ownership, and reversible teardown.
2. Add sqlc CRUD queries matching the management persistence interface, keeping owner-scoped domain reads from leaking another user's registration.
3. Regenerate checked-in sqlc bindings and verify generation drift, build, vet, and tests before committing, rebasing, and pushing.

## Task 11: PostgreSQL BYO-domain store

1. Replace the production in-memory implementation with a narrow sqlc-backed adapter that maps database errors to the relay domain contract and preserves owner-scoped reads.
2. Add tests first for conversion, uniqueness, lifecycle updates, ownership hiding, deletion, and persistence across store instances.
3. Wire the adapter and DNS verifier into the management composition root using the existing regional MTA/relay configuration.
4. Run focused tests plus repository build, vet, and test checks; review, commit, rebase, and push the shared feature branch.

## Task 12: harden explicit pgxpool sizing

1. Add focused tests for defaults, valid overrides, malformed/zero/negative/
   overflowing settings, and `DB_MIN_CONNS <= DB_MAX_CONNS`.
2. Make pool configuration parsing fail closed before opening PostgreSQL while
   retaining the documented defaults.
3. Document and test the per-replica connection budget at the 20-replica HPA
   ceiling, including reserved operational headroom.
4. Run focused and repository validation, then commit, rebase, and push the
   shared feature branch.
