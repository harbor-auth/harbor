## ADDED Requirements

### Requirement: Fail-closed production composition

Each production binary MUST reject missing PostgreSQL, Redis, external URL, or
security-key configuration before serving HTTP. Security-critical constructors
MUST reject missing collaborators and MUST NOT substitute no-op, placeholder,
stub, or in-memory implementations.

#### Scenario: Required dependency is absent

- **Given** a production binary configuration omits a required dependency
- **When** its composition root is started
- **Then** startup fails with a descriptive error before the HTTP listener opens

### Requirement: Durable cross-replica protocol state

The hot production graph SHALL persist clients, grants, consents, refresh
sessions, and revocation state in PostgreSQL and SHALL persist authorization
codes and bounded session state in Redis. It MUST issue asymmetric ES256 or
EdDSA tokens, MUST use pairwise identifiers rather than raw user IDs as token
subjects, and MUST store refresh-token hashes rather than plaintext tokens.

#### Scenario: Authorization and token requests reach different replicas

- **Given** an authenticated authorization request completes on replica A
- **When** its code is exchanged on replica B with an exact redirect URI
- **Then** the exchange succeeds and an `offline_access` grant returns a refresh token

### Requirement: Durable management workflows

The management production graph SHALL persist WebAuthn credentials, enrollment
state, clients, and BYO domains in PostgreSQL and SHALL use Redis for bounded
ceremony and BFF session state. Dynamic registration MUST require its configured
authorization gate. User DEKs MUST remain encrypted at rest and decryption MUST
fail closed on authentication failure without returning partial plaintext.

#### Scenario: Enrollment and registration survive graph reconstruction

- **Given** the management graph is configured with PostgreSQL and Redis
- **When** a user completes passkey enrollment and an authorized client is registered
- **Then** a newly constructed graph can read the persisted credential and client

### Requirement: Consistent deploy-time configuration

Raw Kubernetes manifests and Helm output MUST project the exact environment
names consumed by both binaries, MUST omit development-mode configuration, and
MUST provide one shared user-DEK KEK to both workloads. PostgreSQL pools MUST
have explicit per-replica minimum and maximum connection limits.

#### Scenario: Deployment manifests are rendered

- **Given** valid required chart values
- **When** the chart and raw-manifest contracts are evaluated
- **Then** both workloads receive matching PostgreSQL, Redis, URL, region, WebAuthn, registration, and shared user-DEK KEK configuration

### Requirement: Production scaffolds remain unreachable

Production composition roots MUST NOT import or instantiate test-support memory
stores, development branches, dead bootstrap symbols, noop collaborators, stub
resolvers, or placeholder issuers. The database-backed revocation cache and the
local crypto provider are explicit exceptions.

#### Scenario: Architecture fitness tests inspect composition roots

- **Given** the source trees for both production binaries
- **When** architecture tests inspect imports and constructor symbols
- **Then** forbidden scaffolds are absent and only the documented exceptions remain
