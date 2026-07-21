# Spec: Token revocation endpoint (RFC 7009 — POST /revoke)

Adds a standard, client-facing RFC 7009 `POST /revoke` endpoint on `harbor-hot`
that feeds the shipped internal revocation stack (`revocation-outbox`,
`grant-id-fk`, `bloom-filter-revocation`). Defines the contract and client
authentication, refresh-token and access-token revocation semantics, the
uniform anti-enumeration `200` response, and the requirement that `/revoke`
sits behind the hot-path rate limiter.

## ADDED Requirements

### Requirement: REQ-001 Client-authenticated POST /revoke contract

The system SHALL expose `POST /revoke` on `harbor-hot`, defined in
`api/openapi/harbor.yaml`, accepting an `application/x-www-form-urlencoded` body
with `token` (required) and `token_type_hint` (optional), and MUST require a
valid registered client credential (HTTP Basic auth).

An anonymous or invalid-credential request MUST be rejected with `401` and MUST
perform no revocation.

#### Scenario: Anonymous caller is rejected

**Given** a `POST /revoke` request with no client credentials
**When** the endpoint processes it
**Then** it returns `401` and revokes nothing

#### Scenario: Authenticated well-formed request is accepted

**Given** a `POST /revoke` request with valid client Basic auth and a `token` form field
**When** the endpoint processes it
**Then** it returns `200` with an empty body

#### Scenario: Malformed request is rejected

**Given** an authenticated `POST /revoke` request missing the required `token` field
**When** the endpoint processes it
**Then** it returns `400 invalid_request`

### Requirement: REQ-002 Refresh-token revocation invalidates the grant family

The system SHALL, on revocation of a refresh token owned by the authenticated
client, mark the associated session/grant revoked (`revoked_at`) and invalidate
the whole grant family via the `grant-id-fk` seam.

#### Scenario: Refresh token revokes the grant family

**Given** a valid refresh token owned by the authenticated client
**When** `POST /revoke` is called with that token
**Then** the grant's `revoked_at` is set
**And** the entire grant family is invalidated so a subsequent refresh fails

### Requirement: REQ-003 Access-token revocation records the JTI via the outbox

The system SHALL, on revocation of an access token owned by the authenticated
client, record the token's JTI through the shipped `revocation-outbox` →
`revoked_jtis` path so the bloom filter and `/introspect` subsequently report
the token inactive.

#### Scenario: Access token becomes inactive at /introspect

**Given** a valid access token owned by the authenticated client
**When** `POST /revoke` is called with that token
**And** the token's JTI is subsequently checked via `/introspect`
**Then** `/introspect` reports `active: false`

### Requirement: REQ-004 Uniform 200 response resists enumeration

The system SHALL return `200` with an empty body for every well-formed,
authenticated request — including unknown, expired, already-revoked, and
cross-client tokens — performing revocation only where the token is owned by
the authenticated client. The response and its timing MUST NOT distinguish an
existing token from a non-existing one, and a cross-client token MUST NOT yield
`403` or any metadata leak.

#### Scenario: Unknown token returns 200 with no state change

**Given** an authenticated `POST /revoke` request for a token that does not exist
**When** the endpoint processes it
**Then** it returns `200` with an empty body and changes no state

#### Scenario: Cross-client token returns 200 without revoking

**Given** an authenticated `POST /revoke` request for a token owned by a different client
**When** the endpoint processes it
**Then** it returns `200` with an empty body
**And** performs no revocation and leaks no metadata (no `403`)

#### Scenario: Already-revoked and expired tokens return 200

**Given** an authenticated `POST /revoke` request for an already-revoked or expired token
**When** the endpoint processes it
**Then** it returns `200` with an empty body, indistinguishable from a live-token revocation

### Requirement: REQ-005 Revoke endpoint sits behind the rate limiter

The system SHALL register `/revoke` on the hot-path router behind the
rate-limiter middleware, so that abusive request volume is throttled by the
same limiter that protects the other hot-path endpoints.

#### Scenario: Revoke is rate-limited

**Given** the hot-path router with the rate-limiter middleware installed
**When** `/revoke` is registered
**Then** requests to `/revoke` pass through the rate-limiter middleware before the handler
