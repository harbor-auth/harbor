# Specification: Non-KMS security remediation

## ADDED Requirements

### Requirement: Production composition fails closed

Production services MUST use durable database and Redis implementations for
clients, grants, consents, sessions, enrollment, revocation, and ceremony state.
They MUST reject missing required dependencies, external KMS configuration,
and reachable demo, in-memory, no-op, stub, or local-crypto paths before serving.

#### Scenario: A production prerequisite is absent

```gherkin
Given either production service is configured without a required durable dependency or external KMS setting
When its production composition root starts
Then startup fails before the HTTP listener accepts traffic
And no scaffold implementation is substituted
```

### Requirement: Token consumers share durable authentication and verification

OIDC endpoints MUST authenticate registered public and confidential clients by
their allowed method and hashed secret policy. Userinfo, introspection,
revocation, and logout MUST apply shared issuer, audience, token-type, temporal,
JTI, scope, algorithm, kid, rotation, and durable revocation checks appropriate
to the endpoint, without administrative or cross-client bypasses.

#### Scenario: A token violates shared policy

```gherkin
Given a token has the wrong type, issuer, audience, algorithm, key, time bounds, scope, or revoked JTI
When a token-consuming endpoint receives it
Then the endpoint rejects it or reports it inactive as required by its protocol
And an ID token is never accepted as a userinfo access token
```

### Requirement: Authorization lifecycle state is explicit and replica-safe

First consent and scope escalation MUST require explicit approval, and approval
MUST be consumed once before updating the canonical grant. Revocation, logout,
refresh reuse, and disconnect MUST persist their effects transactionally and
propagate them across replicas through durable state.

#### Scenario: Two replicas process the same lifecycle event

```gherkin
Given two replicas concurrently process one consent, refresh, logout, or revocation event
When both attempt to commit the event
Then durable atomic state admits only the valid transition
And every replica subsequently observes the resulting grant or revocation state
```

### Requirement: Recovery and step-up are bound to distributed sessions

Recovery-required BFF sessions MUST be limited to enrollment operations.
WebAuthn enrollment and ceremony state MUST be shared through Redis. Successful
MFA MUST stamp only the authenticated BFF session, and sensitive management
routes MUST require that step-up while enforcing shared user, session, and IP
limits that deny access on backend failure.

#### Scenario: One browser steps up during recovery

```gherkin
Given a user has two BFF sessions and one is recovery-required
When that browser completes enrollment and MFA verification
Then only its authenticated session receives the step-up stamp
And the other session cannot use that stamp on a sensitive route
```

### Requirement: Browser and WebAuthn mutations resist races and expiry

Authorization completion MUST atomically consume a nonce-bound continuation
before redirect or code issuance. Redis mutations MUST reject missing records or
records with non-positive TTL without recreating them. WebAuthn counter updates
MUST be conditional and MUST reject zero-row, stale, no-op, or regressing
updates except a supported zero-counter authenticator remaining at zero.

#### Scenario: Concurrent requests race on one record

```gherkin
Given concurrent requests use the same continuation or WebAuthn counter value
When their guarded mutations execute
Then at most one state-changing request succeeds
And no expired session, duplicate code, or regressing counter is created
```

### Requirement: Production deployment contracts are invariant

Production MUST reject disabled abuse controls and invalid HTTPS origins or
hosts, and relay authentication MUST fail closed outside development. Helm and
raw manifests MUST agree on required Redis, external KMS, secret, runtime, and
immutable-image contracts, enforce signature policy, and constrain egress.

#### Scenario: A rendered production variant weakens a contract

```gherkin
Given a Helm or raw production manifest omits a required secret, uses a mutable image, disables authentication, or broadens egress
When deployment contract validation runs
Then validation fails
And no KMS credential or local production key is synthesized
```
