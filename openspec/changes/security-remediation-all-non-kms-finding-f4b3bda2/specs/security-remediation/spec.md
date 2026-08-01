# Security remediation requirements

## ADDED Requirements

### Requirement: Production graphs use only durable security dependencies
In production, harbor-hot and harbor-mgmt SHALL refuse startup unless their database, Redis, regional KMS, verification, revocation, enrollment, authorization, and worker dependencies are configured, and SHALL expose no demo, in-memory, no-op, placeholder, or stub path.

#### Scenario: Missing production prerequisite
- **WHEN** either binary starts in production without any required durable dependency or regional KMS configuration
- **THEN** startup fails before serving traffic and does not substitute a local implementation

#### Scenario: Complete production graph
- **WHEN** production starts with valid PostgreSQL, Redis, and external KMS configuration
- **THEN** live requests use durable clients, codes, grants, sessions, revocations, enrollment sessions, and verification across replicas

### Requirement: Token consumers share authenticated lifecycle policy
Harbor SHALL authenticate registered clients according to their public or confidential method and SHALL apply one JWT policy to userinfo, introspection, revocation, logout, and related token consumers.

#### Scenario: Invalid or cross-client token request
- **WHEN** a caller supplies an invalid client secret, wrong audience, wrong token type, unsupported algorithm, stale kid, missing scope, expired token, or revoked JTI
- **THEN** the request is rejected without an admin or cross-client bypass

#### Scenario: Key rotation and revocation propagation
- **WHEN** keys rotate or a token/session is revoked on one replica
- **THEN** all replicas converge through durable state and publication while valid tokens from retained keys continue according to policy

### Requirement: Consent is explicit and canonical
Harbor SHALL require explicit approval for first consent and scope escalation, honor OIDC prompt semantics, and use one canonical grant for authorization, dashboard disconnect, refresh, logout, and revocation.

#### Scenario: Consent approval
- **WHEN** a user approves a first grant or scope escalation
- **THEN** Harbor persists the canonical grant only after approval and resumes authorization once

#### Scenario: Consent denial or disconnect
- **WHEN** the user denies consent or disconnects a client
- **THEN** no new grant is written and the canonical grant plus related sessions are transactionally revoked

### Requirement: Recovery and MFA are session-bound and distributed
Harbor SHALL propagate recovery state into BFF sessions, restrict recovery sessions to enrollment-only routes, bind MFA verification and step-up to the authenticated BFF session, and enforce distributed per-user, session, and IP throttling/lockout.

#### Scenario: Recovery-scoped route access
- **WHEN** a recovery-required session calls a sensitive route outside enrollment or recovery completion
- **THEN** the route is denied regardless of replica

#### Scenario: MFA step-up
- **WHEN** MFA succeeds for an authenticated BFF session
- **THEN** step-up is recorded on that session and StepUpGate permits only that session until expiry

### Requirement: Browser and authenticator state transitions are race-safe
Harbor SHALL atomically consume authorization completion state, require production browser nonce binding, preserve positive Redis TTLs without resurrection, and atomically advance WebAuthn sign counts.

#### Scenario: Concurrent completion
- **WHEN** two requests race to complete one authorization or update one credential counter
- **THEN** exactly one succeeds and the stale request fails safely

#### Scenario: Expired Redis state
- **WHEN** a mutation targets a missing, expired, or non-positive-TTL session
- **THEN** it returns not found/expired and does not recreate the key

### Requirement: Production abuse and deployment controls fail closed
Harbor SHALL prohibit disabled sensitive-endpoint limits in production, validate HTTPS URLs/origins/hosts, require relay authentication, use immutable verified images, align raw and Helm secret/environment contracts, and limit egress.

#### Scenario: Unsafe production configuration
- **WHEN** production configuration contains disabled limits, insecure URLs, missing relay auth, mutable images, missing Redis/KMS contracts, or broad egress
- **THEN** startup or deployment validation fails

#### Scenario: Redis outage
- **WHEN** Redis is unavailable during a sensitive request including MFA or recovery
- **THEN** the endpoint uses an explicitly bounded local policy or fails closed and never becomes unlimited
