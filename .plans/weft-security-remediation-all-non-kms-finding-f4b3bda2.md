# Security remediation: all non-KMS findings

## Task 1: failing harbor-hot production graph tests

1. Capture the production startup contract for PostgreSQL, Redis, external KMS, and every durable OIDC dependency.
2. Add a live-graph source guard proving production assembly cannot instantiate demo, placeholder, local-crypto, in-memory, stub, or no-op implementations.
3. Add a signing bootstrap regression test rejecting a local key provider in production.
4. Run the focused package test and confirm the new tests fail for the intended missing production wiring.
5. Commit, rebase on the shared branch, and push the red-test task for the implementation task to satisfy.

## Task 16: recovery and enrollment scope tests

1. Inspect the BFF recovery-session model, management authorization gates, and WebAuthn Redis stores.
2. Add focused negative tests proving `recovery_required` is propagated and restricts a session to enrollment operations.
3. Add cross-replica enrollment tests proving both the enrollment handoff and WebAuthn ceremony state use Redis.
4. Run the focused tests and confirm they fail for the intended missing production behavior, then run formatting and compile checks.
5. Rebase the shared branch, commit, push, and report task completion.

## Task 18: session-bound MFA and lockout tests

1. Add handler tests that require MFA identity and the step-up stamp to be tied
   to the authenticated BFF session, with missing session state failing closed.
2. Extend step-up gate coverage for session isolation and store outages.
3. Add shared-Redis tests for per-user, per-session, and per-IP limits across
   limiter instances, including outage behavior.
4. Add an end-to-end assertion that MFA step-up applies only to the browser
   session that completed verification.
5. Run the focused tests and record the expected pre-implementation failure.

The Task 18 pre-work pull/rebase was attempted, but the assigned shared branch
did not yet exist on `origin`; the required pre-push rebase incorporated Task 1.

## Task 12: explicit consent red tests

1. Extend core authorize tests to pin `prompt=none`, `prompt=consent`, first-consent, and scope-escalation behavior without implicit grant persistence.
2. Extend the assembled BFF flow tests to require a consent hand-off after authentication, explicit approval/denial, and one-time decision consumption.
3. Run focused tests to verify the new security tests fail for the current implicit-consent behavior.
4. Format, commit, rebase on the shared branch, push, and report task completion.

## Task 22: concurrent WebAuthn sign-count tests

1. Model the guarded credential counter update in the DB-store fake, including a hook that simulates another replica winning between the read and update.
2. Add DB-store tests for stale concurrent updates, guarded no-ops, and authenticators that do not implement a signature counter (zero to zero).
3. Run the focused WebAuthn tests and confirm the new security assertions fail for the expected reason, then commit, rebase, and push the test-only change.

## Task 10: multi-replica revocation lifecycle tests

1. Inspect the revocation worker, durable outbox, revoked-JTI store/pub-sub, refresh reuse, and logout lifecycle seams.
2. Add focused red tests for persistence-before-acknowledgement, concurrent replica claiming, restart recovery, pub/sub propagation, and shared refresh-family revocation.
3. Run the scoped tests and confirm each new test fails for the intended missing behavior while existing tests still pass.
4. Format, commit, rebase the shared branch if it exists, and push the test-only change.

Pre-work rebase note: `origin/weft/security-remediation-all-non-kms-finding-f4b3bda2` did not exist when the task started, so the checkout was initially based on `origin/main` (`8f308f8`). The required pre-push rebase incorporated the other published test tasks.

## Task 23: reject no-op and regressing WebAuthn counter updates

1. Change the guarded sign-count query to expose its affected-row count and regenerate sqlc output.
2. Treat a zero-row guarded update as a counter regression while preserving the valid zero-to-zero authenticator exception.
3. Ensure the store regression sentinel is recognizable as the service clone signal and update narrow test fakes for the generated interface.
4. Run focused WebAuthn tests, formatting, build/vet, the full Go suite, agent checks, and generation drift checks.
5. Commit, rebase on the shared branch, push, store the result in Hippo, and complete the Weft task.

## Task 14: canonical grants ledger migration

1. Backfill each active legacy consent into its existing canonical grant and
   fail the migration if a consent has no grant carrying its region and PPID.
2. Replace the legacy consent table with a compatibility view over `grants` so
   there is only one authority during the dependent application rollout.
3. Add canonical scope-update and atomic grant-plus-session revocation queries.
4. Regenerate sqlc output and run migration/code-generation and Go checks.
5. Rebase the shared branch, commit, push, and report task completion.

## Task 11: replica-safe revocation and theft handling

1. Run the focused revocation lifecycle tests from Task 10 and confirm their intended failures.
2. Make outbox delivery claim-safe and acknowledgement failures observable, drain durable work immediately on worker startup, and make refresh rotation a database compare-and-swap.
3. Verify durable JTI propagation and shared logout/theft behavior with the focused clients, OIDC, and OIDC API suites, including race coverage.
4. Run repository validation, commit, rebase the shared branch, and push.

## Task 13: explicit one-time BFF consent approval

1. Preserve OIDC prompt state in the nonce-bound BFF authorization session.
2. Hand authenticated requests requiring interaction to an explicit approve or deny form.
3. Atomically consume the pending session before applying a decision; persist consent only on approval.
4. Keep prompt=none, first-consent, scope-escalation, denial, and replay behavior fail-closed.
5. Run focused and repository checks, rebase, commit, and push.

## Task 15: canonical grants across authorization and disconnect

1. Add regression tests proving approved scope escalation updates the existing
   canonical grant instead of revoking and recreating it.
2. Expose canonical grant listing and an atomic grant-plus-session revocation
   operation from both database and in-memory stores.
3. Move management and dashboard connected-app reads and disconnect mutations
   to the canonical grant contract, removing the two-step session cascade.
4. Run focused race tests and the repository validation suite.
5. Rebase the shared branch, commit, push, and report task completion.
