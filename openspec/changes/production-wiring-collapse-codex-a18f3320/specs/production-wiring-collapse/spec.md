# Production wiring collapse specification

## Requirement: Required infrastructure

Both shipped binaries MUST require reachable Postgres and Redis dependencies and MUST fail startup with an actionable error when either dependency or required configuration is absent. Pool sizing MUST be explicit.

### Scenario: Missing dependency

- **WHEN** either binary starts without its Postgres or Redis configuration
- **THEN** startup fails before an HTTP server is exposed
- **AND** no in-memory or noop substitute is selected

## Requirement: One hot-path graph

The hot binary MUST use the DB client, session, grant, consent, signing and revocation implementations plus Redis authorization-code, BFF-session, and rate-limit implementations. It MUST NOT register a demo client or use a placeholder issuer or fixed session resolver.

### Scenario: Cross-replica token exchange

- **WHEN** authorization is completed through one hot handler instance
- **AND** its code is exchanged through another instance sharing Postgres and Redis
- **THEN** token exchange succeeds
- **AND** an `offline_access` grant produces a persisted refresh token

## Requirement: One management graph

The management binary MUST use DB-backed credential, enrollment, client-registration, consent, session, dashboard, and domain persistence plus Redis-backed ceremony and BFF sessions. Enrollment sessions MUST be attached to both management and WebAuthn handlers, and dynamic registration MUST enforce the configured initial access token.

### Scenario: Enrollment and registration

- **WHEN** an enrolled user completes a passkey ceremony
- **THEN** the ceremony resolves the enrollment session without a 501 response
- **AND WHEN** an authorized caller registers a client
- **THEN** the client persists and is visible to the hot binary

## Requirement: Deployment contract

Helm and reference Kubernetes manifests MUST supply environment names exactly as read by the binaries, including Redis for management, region, login/continuation URLs, separate signing KEK, and a shared user-DEK KEK consumed by both components.

### Scenario: Rendered deployment

- **WHEN** the Helm chart and Kustomize base are rendered
- **THEN** both deployments contain all required non-secret and secret references
- **AND** no obsolete environment name or development-mode escape remains

## Requirement: No production scaffolds

Command packages MUST NOT import or instantiate in-memory test stores, noop collaborators, placeholder issuers, or stub identity resolvers. Deliberate revocation caches and the local crypto implementation are exempt.

### Scenario: Architecture regression check

- **WHEN** architecture and live-graph tests inspect both boot paths
- **THEN** only persistent production implementations are reachable
- **AND** the permitted revocation caches and local crypto provider remain available
