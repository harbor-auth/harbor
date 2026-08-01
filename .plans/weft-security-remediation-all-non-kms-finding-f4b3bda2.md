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
