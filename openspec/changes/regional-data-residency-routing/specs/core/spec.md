# Spec: Regional data-residency routing (region-pinned, fail-closed)

Makes region a first-class, request-scoped, fail-closed property: a total
host/issuer → region resolver, a region-pinned request context that binds
datastore selection, a cross-region PII guard that fails closed with no partial
data, and issuer/host region coherence across the token lifecycle. Realises the
§5 residency boundary with no cross-region replication or lookup.

## ADDED Requirements

### Requirement: REQ-001 Total host → region resolution

The system SHALL resolve the active region for an inbound request from its host
(or issuer prefix) via an explicit, startup-validated map. Resolution MUST be
total: an unrecognised host MUST be rejected and MUST NEVER be defaulted to any
region.

#### Scenario: Known region host resolves

**Given** a request to host `eu.harbor.id`
**When** the region is resolved
**Then** the region resolves to `eu`

#### Scenario: Unknown host is rejected, not defaulted

**Given** a request to an unrecognised host `unknown.example`
**When** the region is resolved
**Then** the request is rejected and no region is selected

### Requirement: REQ-002 Region-pinned request context

The system SHALL carry the resolved region on the request context and bind
datastore selection to it. `region.FromContext` MUST fail closed (return an
error) when the region is unset, and a handler MUST NOT be able to reach another
region's datastore.

#### Scenario: FromContext fails closed when unset

**Given** a context with no pinned region
**When** a handler calls `region.FromContext`
**Then** it returns an error and the handler does not proceed to a user-data read

#### Scenario: Datastore selection is pinned

**Given** a request pinned to region `eu`
**When** a handler selects a datastore
**Then** only the `eu` datastore is reachable

### Requirement: REQ-003 Cross-region PII guard fails closed

The system SHALL, when a handler would read a user whose region differs from the
request's pinned region, return a defined error, meter the event with no PII,
and return NO partial data.

#### Scenario: Foreign-region read returns no data

**Given** a request pinned to region `eu`
**When** a handler attempts to read a user resident in region `us`
**Then** a defined error is returned, the event is metered without PII, and no user data is returned

### Requirement: REQ-004 Issuer/host region coherence

The system SHALL ensure a token's `iss`, and the userinfo and introspection
hosts, are region-coherent with the resolving host, so a token minted in one
region is only ever verified or introspected on that region's issuer surface.

#### Scenario: Token is region-coherent

**Given** a token minted on the `eu` issuer
**When** it is introspected
**Then** it is accepted only on the `eu` introspection surface and its `iss` is the `eu` issuer

### Requirement: REQ-005 home_region is per-region authoritative; no cross-region user lookup on the guard path

A user's authoritative `home_region` SHALL be stored only in that user's
home-region datastore. The cross-region guard MUST derive the request's region
from the host/issuer prefix and MUST NOT perform any global user-directory
lookup to discover a user's region. If a routing index (`user_id → region`) is
ever introduced, it MUST be PII-free (opaque `user_id` → region code only — no
email/name/subject).

#### Scenario: Guard fails closed without a cross-region lookup

**Given** a request pinned to region `eu` targeting a user resident in region `us`
**When** the guard evaluates the read
**Then** it derives the request region from the host, performs no global directory lookup to discover the user's region, and fails closed with no partial data

#### Scenario: Any routing index is PII-free

**Given** an optional `user_id → region` routing index
**When** its rows are inspected
**Then** each row holds only an opaque `user_id` and a region code — no email, name, or subject
