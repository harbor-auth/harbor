## ADDED Requirements

### Requirement: Production binaries construct one durable graph

Harbor-hot and harbor-mgmt SHALL require reachable PostgreSQL and Redis services and SHALL construct all security- and durability-critical seams from DB- or Redis-backed implementations.

#### Scenario: Required services are available

- **WHEN** either binary starts with valid database, Redis, region, URL, crypto, and authentication configuration
- **THEN** startup constructs the complete durable handler graph without an in-memory, noop, stub, or placeholder collaborator

#### Scenario: A required dependency is missing

- **WHEN** a required URL, client, pool, store, or crypto dependency is absent or nil
- **THEN** construction fails with a clear startup error before serving traffic

### Requirement: Hot-path state works across replicas

Authorization codes, refresh sessions, grants, consents, registrations, and revocation delivery SHALL use shared durable stores.

#### Scenario: Authorization code crosses replicas

- **WHEN** replica A issues an authorization code and replica B receives its valid token exchange
- **THEN** replica B consumes the code exactly once and returns tokens

#### Scenario: Offline access is granted

- **WHEN** an authorized client completes a valid flow with `offline_access` and a persisted grant
- **THEN** the token response includes a persisted refresh token

### Requirement: Management enrollment and registration are fully wired

The management graph SHALL use Redis-backed enrollment sessions on both the management server and WebAuthn handler, DB-backed WebAuthn/user/BYO-domain stores, and gated DB-backed client registration.

#### Scenario: Passkey enrollment completes

- **WHEN** a user begins and finishes a valid enrollment ceremony
- **THEN** the same enrollment session is resolved by all ceremony handlers and the credential and user are persisted without a 501 or fallback 503

#### Scenario: Dynamic registration is attempted

- **WHEN** a caller presents the configured initial access token and valid registration metadata
- **THEN** the client is persisted in PostgreSQL and is visible to the hot client registry

### Requirement: Production scaffolds are unreachable

Production command packages SHALL NOT import or instantiate in-memory stores, noop stores, fixed authentication sources, placeholder issuers, or memory-only rate limiters.

#### Scenario: Architecture checks inspect command wiring

- **WHEN** architecture and live-graph tests run
- **THEN** they prove the two command graphs contain no forbidden scaffold while allowing the durable-backed revocation cache and documented local crypto exception

### Requirement: Deployment configuration matches runtime names

Raw Kubernetes, Helm, and compose configurations SHALL supply every runtime-required variable under the exact name read by the binaries.

#### Scenario: Manifests are rendered

- **WHEN** Helm templates and raw Kubernetes resources are rendered and inspected
- **THEN** both workloads receive PostgreSQL, Redis, region, URL, WebAuthn, and crypto values with no obsolete `HARBOR_DEV_MODE` or mismatched environment names

#### Scenario: User DEK crosses binary boundary

- **WHEN** management wraps a user's DEK and hot later derives the user's PPID
- **THEN** both binaries consume the same explicit `global.userDekKekSecret` as `HARBOR_KMS_SECRET`, distinct from the signing-key KEK

### Requirement: Connection pools are bounded

Every PostgreSQL pool SHALL set and validate explicit maximum, minimum, and lifetime settings appropriate for the deployment replica ceiling.

#### Scenario: Default pool configuration is built

- **WHEN** a binary connects without pool-size overrides
- **THEN** pgxpool receives documented non-zero limits whose aggregate deployment budget is accounted for
