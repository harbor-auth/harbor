# Security remediation: all non-KMS findings

## Task 5: startup runtime and KMS contracts

1. Add focused configuration tests for strict runtime-mode parsing, production
   KMS requirements, and explicitly configured development-only local crypto.
2. Centralize the runtime and key-provider configuration contract in
   `internal/crypto` and remove implicit development key material.
3. Make harbor-hot and harbor-mgmt select their startup graph from the shared
   mode contract and consume the same production KMS key map.
4. Run focused tests and repository validation, then rebase, commit, and push.

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

## Task 8: shared JWT policy red tests

1. Define a table-driven verifier contract for issuer, audience-bearing access
   tokens, expiry/issued-at/JTI/scope claims, JOSE type/algorithm/kid, key
   rotation overlap, and durable revocation failures.
2. Exercise the same contract at userinfo and introspection, including explicit
   ID-token rejection at userinfo and inactive introspection responses.
3. Pin logout to genuine ID-token hints while retaining the specified expired
   ID-token behavior and client audience binding.
4. Run the focused suites and confirm the new cases fail for missing shared
   policy behavior without changing production code.
5. Format, commit, rebase on the shared branch, push, and report completion.

## Task 9: shared JWT verifier implementation

1. Consolidate JOSE header, rotating-key, issuer, temporal, token-type, claim,
   scope, audience, and durable revocation checks in `oidc.JWTVerifier`.
2. Construct one verifier in the OIDC API server and use it for userinfo,
   introspection, access-token revocation, and logout ID-token hints.
3. Preserve endpoint-specific behavior: userinfo/revocation require access
   tokens, introspection applies caller audience isolation, and logout accepts
   expired genuine ID tokens but rejects access tokens.
4. Run focused tests, race checks, repository build/vet/test gates, agent and
   generation checks, then rebase, commit, and push the shared branch.

## Task 3: harbor-mgmt production graph tests

1. Capture the production startup dependency contract at the `cmd/harbor-mgmt` boundary.
2. Assert the live production assembly contains durable PostgreSQL/Redis-backed stores, a real WebAuthn handler, and no reachable scaffold or duplicate enrollment route.
3. Assert production dynamic registration fails closed without an initial access token while explicitly opted-in development registration may remain open.
4. Run the focused tests and confirm they fail for the missing Task 4 production wiring, then format, commit, rebase, and push.

## Task 6: durable client authentication red tests

1. Pin the OIDC domain contract for public and confidential clients, SHA-256
   secret hashes, uniform mismatch errors, and unsupported authentication
   methods.
2. Add introspection and revocation negatives for missing, wrong, public-client,
   unknown-client, and cross-client credentials.
3. Add token endpoint parity tests for `none`, `client_secret_basic`, and
   `client_secret_post`, including method mismatch and credential conflicts.
4. Run the focused suites and confirm the new tests fail for the missing shared
   authenticator without weakening existing assertions.
5. Rebase the shared branch, commit the test-only contract, and push.

## Task 21: atomic BFF continuation and Redis mutations

1. Run the Task 20 race and expiry tests to identify the remaining unsafe paths.
2. Keep authorization-code issuance behind the session store's atomic one-time consume gate and preserve nonce, PKCE, CSRF, cookie, and ownership validation.
3. Make every Redis session mutation reject missing keys and keys without a positive remaining TTL without rewriting the record.
4. Run focused BFF/OIDC API tests, race coverage, and repository validation.
5. Rebase the shared branch, commit, push, and report task completion.

## Task 20: BFF consume and Redis expiry race tests

1. Add concurrent authorize-completion coverage proving exactly one request can
   consume a nonce-bound authenticated session and redirect with a code.
2. Inject a session-store consume failure and prove completion fails closed
   without an RP redirect or authorization code.
3. Cover missing and non-expiring Redis records across every session mutation,
   requiring an error and no record recreation or mutation.
4. Retain the production nonce-gate coverage for legacy records at login and
   authorize completion, then run focused tests and capture expected failures.
5. Format, commit, rebase the shared branch, push, and report task completion.

## Task 2: durable harbor-hot production graph

1. Isolate all scaffold construction behind the explicit development mode.
2. Assemble the production OIDC graph from one PostgreSQL pool and one Redis client.
3. Rehydrate and subscribe the revoked-JTI filter, start the durable outbox worker,
   and share the JWT verifier with logout and token consumers.
4. Require an external KMS provider and validate every production dependency
   before the HTTP listener starts.
5. Run focused and repository validation, rebase, commit, and push.

## Task 4: durable harbor-mgmt production graph

1. Isolate production startup from explicitly opted-in development scaffolds.
2. Compose PostgreSQL-backed identity, grants, sessions, registration, recovery,
   MFA, and WebAuthn stores with Redis-backed BFF, enrollment, and ceremony state.
3. Serve the real WebAuthn handler and require an initial-access token or an
   authenticated administrator for dynamic client registration.
4. Run focused production-graph and management tests, then repository checks.
5. Rebase the shared branch, commit, push, record the result, and complete the task.

## Task 24: production abuse configuration red tests

1. Pin production startup to reject `RATE_LIMIT_DISABLED` and non-HTTPS issuer,
   login, registration, WebAuthn origin, and relying-party host configuration.
2. Require rate-limiter backend failures to stop token requests instead of
   passing them through.
3. Add a management composition-root contract requiring outage-aware abuse
   gates on MFA, recovery, enrollment, and dynamic-registration endpoints.
4. Run the focused suites and confirm the new assertions fail for the intended
   missing hardening, then format, commit, rebase, and push the test-only work.

## Task 26: relay authentication mode red tests

1. Pin startup configuration so production requires authentication enforcement
   while an explicit development/test mode may retain monitoring behavior.
2. Add a request-time backstop proving an enforced relay cannot accept mail
   when its authenticator dependency is absent.
3. Run the focused command and relay package tests and confirm the new contracts
   fail for the intended missing mode validation and fail-open request path.
4. Format, commit, rebase the shared branch, push, and report task completion.

## Task 7: durable OIDC client authenticator

1. Extend the OIDC client model and durable registry mapping with the registered token endpoint authentication method and secret hash.
2. Implement one constant-time client authenticator shared by direct service calls and HTTP endpoints.
3. Parse token endpoint Basic/post credentials, reject conflicts and method mismatches before consuming authorization codes or rotating refresh tokens.
4. Require confidential client authentication for introspection and revocation and preserve cross-client isolation without an admin bypass.
5. Run focused and repository checks, rebase the shared branch, commit, push, and report task completion.

## Task 27: require relay authentication outside development

1. Run the relay authentication contract tests from Task 26 and confirm the intended startup and request-path failures.
2. Resolve authentication enforcement explicitly from development mode and reject production startup without the required authenticator configuration.
3. Make the SMTP request path fail closed whenever enforcement is enabled but no authenticator is available, retaining monitoring-only scaffold behavior solely in explicit development mode.
4. Run focused relay tests plus repository formatting, build, vet, test, agent, and generation checks.
5. Rebase the shared branch, commit, push, store the result in Hippo, and complete the Weft task.
