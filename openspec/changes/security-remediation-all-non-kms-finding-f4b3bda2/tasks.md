# security-remediation-all-non-kms-finding-f4b3bda2 — Tasks

## Production object graph

- [x] Add production graph tests for harbor-hot and harbor-mgmt.
- [x] Wire durable stores, workers, verifiers, registration authorization, and
      external-KMS startup prerequisites.
- [x] Reconcile runtime, Redis, KMS, image, Helm, and raw-manifest contracts.

## OIDC lifecycle

- [x] Implement and apply one durable client authenticator.
- [x] Implement and apply one shared JWT verification policy.
- [x] Make revocation, refresh-theft handling, logout, and outbox delivery
      durable and replica-safe.

## Consent, recovery, and MFA

- [x] Require explicit, one-time consent and use the canonical grants ledger.
- [x] Propagate recovery scope and use distributed enrollment/WebAuthn state.
- [x] Bind MFA step-up and shared abuse controls to BFF sessions.

## BFF and WebAuthn correctness

- [x] Atomically consume continuations and reject invalid Redis TTL mutations.
- [x] Require browser nonce binding and reject stale WebAuthn counter updates.

## Deployment hardening and verification

- [x] Fail closed on production abuse, URL, and relay misconfiguration.
- [x] Test Helm and raw security contracts and signed digest publication.
- [x] Run assembled cross-replica security integration checks.
- [x] Run strict OpenSpec validation.
