# Security remediation: all non-KMS findings

## Why

Harbor's durable security primitives exist on `main`, but several production entrypoints still compose demo, in-memory, no-op, or partially authenticated paths. This makes the assembled service weaker than its individual packages and creates replica-local behavior for authorization, revocation, enrollment, MFA, and abuse controls.

## What changes

- Fail production startup closed unless the hot and management object graphs have durable PostgreSQL, Redis, regional KMS, verification, revocation, and authorization dependencies.
- Unify OIDC client authentication and JWT validation across token-consuming endpoints, with durable multi-replica revocation.
- Make consent, recovery, enrollment, and MFA session-bound, explicit, durable, and transactionally revocable.
- Make BFF completion and WebAuthn counters race-safe and one-time.
- Harden production URL, rate-limit, relay, image, secret, environment, KMS, Redis, and egress deployment contracts.

## Scope

This is security-only remediation. It does not provision or emulate OVH KMS; regional KMS keys and credentials remain external prerequisites. Local crypto is permitted only in explicit development/test mode.

## Success criteria

Production live-graph and cross-replica integration tests prove no scaffold path is reachable, all negative token/consent/recovery/race cases fail closed, raw and Helm deployment variants render the same required contracts, and the full repository and release verification gates pass.
