# Implementation checklist

## A. Production object graph and startup

- [ ] Add failing production live-graph tests for harbor-hot and harbor-mgmt scaffold reachability.
- [ ] Wire harbor-hot durable stores, shared verifier, revocation worker/subscriber, logout, and session revocation; require external KMS in production.
- [ ] Wire harbor-mgmt PostgreSQL/Redis WebAuthn, enrollment, grant/session, MFA/recovery, and protected registration dependencies.
- [ ] Reconcile production runtime environment and KMS/Redis contracts between constructors and manifests.

## B. OIDC lifecycle

- [ ] Add negative client-auth and shared-verifier regression tests.
- [ ] Implement a durable public/confidential client authenticator and use it for token, introspection, and revocation policy.
- [ ] Centralize JWT validation for userinfo, introspection, revocation, and logout.
- [ ] Make revocation, refresh reuse/theft, logout, outbox processing, and propagation durable and replica-safe.

## C. Consent, recovery, and MFA

- [ ] Add failing prompt, approval, scope-escalation, recovery-scope, MFA-binding, and lockout tests.
- [ ] Make BFF consent explicit and persist only after approval.
- [ ] Migrate to one canonical grant and transactionally revoke related sessions.
- [ ] Complete distributed enrollment/recovery session wiring and remove the legacy enrollment path.
- [ ] Bind MFA and step-up to BFF sessions with distributed user/session/IP limits.

## D. BFF and WebAuthn correctness

- [ ] Add authorization consume, Redis expiry/resurrection, and concurrent sign-count regression tests.
- [ ] Atomically consume authorization completion and enforce production nonce binding.
- [ ] Prevent Redis mutation scripts from resurrecting expired sessions.
- [ ] Return WebAuthn sign-count affected rows and reject concurrent no-op/regressing updates.

## E. Abuse and deployment hardening

- [ ] Add failing production configuration and Redis-outage tests for rate limits, URLs, and relay auth.
- [ ] Fail closed or use bounded-local limiting on sensitive endpoints and validate production HTTPS origins/hosts.
- [ ] Require relay authentication outside explicit development.
- [ ] Add raw/Helm render tests for immutable images, secrets/env, Redis/KMS, runtime requirements, and narrow egress.

## Integration and release

- [ ] Run full live-graph, cross-replica, OIDC, consent, recovery, enrollment, step-up, recovery-code, Helm, and Kubernetes integration checks.
- [ ] Run OpenSpec verification.
- [ ] Create one pull request against main after all workstreams complete.
- [ ] Poll CI, fix failures, squash-merge, and verify the merged state before feature completion.
