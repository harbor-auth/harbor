# Spec: Dynamic client registration (RFC 7591 / 7592)

Adds RFC 7591 `POST /register` and RFC 7592 `GET/PUT/DELETE /register/{client_id}`
on `harbor-mgmt` over the shipped client registry. Defines registration and
metadata validation, credential minting and hashed-at-rest storage, the
per-client registration-access-token authorisation model (with cross-client
isolation), the optional initial-access-token gate, and the delete cascade.

## ADDED Requirements

### Requirement: REQ-001 RFC 7591 client registration

The system SHALL expose `POST /register` on `harbor-mgmt` that validates
submitted client metadata, mints a `client_id` (and a `client_secret` for
confidential clients), persists the client via the shipped registry, and returns
`201` with the registered metadata plus a `registration_access_token` and
`registration_client_uri`.

#### Scenario: Valid registration returns 201 and a usable client

**Given** a `POST /register` request with valid metadata
**When** the endpoint processes it
**Then** it returns `201` with a `client_id`, a `registration_access_token`, and a `registration_client_uri`
**And** the new client can complete an authorize/token flow

#### Scenario: Invalid metadata is rejected

**Given** a `POST /register` request with a non-exact-match or non-https redirect URI, or an unsupported grant type
**When** the endpoint processes it
**Then** it returns `400 invalid_client_metadata` and persists no client

### Requirement: REQ-002 Credentials are hashed at rest and shown once

The system SHALL store `client_secret` and `registration_access_token` **hashed
only** and MUST return their plaintext exactly once, at creation (and again only
if a `PUT` rotates them).

#### Scenario: Secret and reg-token are returned once

**Given** a successful registration
**When** the `201` response is produced
**Then** the plaintext `client_secret` and `registration_access_token` appear only in that response

#### Scenario: No plaintext secret persisted

**Given** a registered client
**When** its stored row is inspected
**Then** neither the `client_secret` nor the `registration_access_token` is present in plaintext

### Requirement: REQ-003 RFC 7592 management authorised by the per-client reg-token

The system SHALL authorise `GET/PUT/DELETE /register/{client_id}` by the
per-client `registration_access_token`. `GET` returns the current config, `PUT`
re-validates and replaces the mutable metadata; a missing or invalid reg-token
MUST return `401`.

#### Scenario: GET returns config with a valid reg-token

**Given** a client and its `registration_access_token`
**When** `GET /register/{client_id}` is called with that token
**Then** it returns the client's current configuration

#### Scenario: Missing reg-token is rejected

**Given** a `PUT /register/{client_id}` request with no reg-token
**When** the endpoint processes it
**Then** it returns `401` and changes nothing

### Requirement: REQ-004 Cross-client isolation

The system SHALL ensure a `registration_access_token` issued for one client
cannot read, modify, or delete a different client, returning `401`/`403` with no
metadata leak.

#### Scenario: Client A's reg-token cannot touch client B

**Given** clients A and B, and A's `registration_access_token`
**When** that token is used against `/register/{B}`
**Then** the request is rejected (`401`/`403`) and no B metadata is returned

### Requirement: REQ-005 Optional initial-access-token gate on registration

The system SHALL support a configurable requirement that `POST /register`
present a valid initial access token; when the requirement is enabled, an
unauthenticated registration MUST be rejected with `401`.

#### Scenario: Gated registration rejects anonymous callers

**Given** initial-access-token gating is enabled
**When** a `POST /register` request arrives without a valid initial access token
**Then** it returns `401` and persists no client

### Requirement: REQ-006 Delete cascade-revokes the client's grants

The system SHALL, on `DELETE /register/{client_id}`, remove the client and
cascade-revoke its outstanding grants via the shipped revocation stack.

#### Scenario: Deleting a client revokes its grants

**Given** a registered client with outstanding grants
**When** `DELETE /register/{client_id}` succeeds with the correct reg-token
**Then** the client is removed and its outstanding grants are revoked
