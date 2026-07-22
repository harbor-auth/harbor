# Spec: Email relay service (per-RP Hide-My-Email)

Mints one opaque, unlinkable relay address per `(user, RP)` grant; stores the
mapping envelope-encrypted and region-pinned (never cross-region); runs a
Go-native regional inbound MTA that enforces SPF/DKIM/DMARC, ARC-seals, and
forwards with no content retention; and provides an instant hard-bounce kill
switch independent of the login grant. Realises §7.5 with no external-SaaS
callout on the inbound PII path.

## ADDED Requirements

### Requirement: REQ-001 Opaque, unlinkable per-(user, RP) address

The system SHALL mint exactly one relay address
`<opaque-token>@relay.<region>.harbor.id` per `(user, RP)` grant. The
`<opaque-token>` MUST be randomly generated and unlinkable — NOT derived from the
user id in any RP-reversible way — so two RPs' relay addresses for the same user
are uncorrelated.

#### Scenario: One unlinkable address per grant

**Given** a user who consents to two different RPs
**When** relay addresses are minted for each grant
**Then** each grant has exactly one relay address and the two addresses are uncorrelated (not derivable from one another or the user id)

### Requirement: REQ-002 Region-pinned, encrypted mapping, never cross-region

The system SHALL store the `relay_address → user → client_id` mapping
envelope-encrypted at rest in the user's home region and MUST NEVER replicate it
cross-region.

#### Scenario: Mapping stays in-region

**Given** an `eu` user's relay address
**When** the mapping store is inspected
**Then** the mapping row is envelope-encrypted, resides only in the `eu` region, and is not present in any other region

### Requirement: REQ-003 Inbound authentication, ARC-seal, forward, no retention

The system SHALL, for inbound mail to a relay address, look up the mapping
(rejecting unknown addresses), authenticate the sender via SPF/DKIM/DMARC
alignment, ARC-seal, and forward to the user's real inbox. It MUST NOT log or
store message bodies.

#### Scenario: Authenticated mail is forwarded, unauthenticated is rejected

**Given** an active relay address
**When** SPF/DKIM/DMARC-aligned mail arrives
**Then** it is ARC-sealed and forwarded to the real inbox, and no message body is logged or stored

#### Scenario: Unknown address is rejected

**Given** mail addressed to a relay token with no mapping
**When** it arrives at the inbound MTA
**Then** it is rejected

### Requirement: REQ-004 Hard-bounce kill switch, independent of the login grant

The system SHALL, when a relay address is Deactivated, refuse inbound mail with a
hard bounce. Deactivation MUST be independent of the RP login grant — deactivating
the relay MUST NOT revoke the login, and revoking the login MUST NOT by itself
deactivate the relay.

#### Scenario: Deactivated address hard-bounces

**Given** a deactivated relay address
**When** mail arrives for it
**Then** the message is refused with a hard bounce

#### Scenario: Kill switch does not revoke login

**Given** an active RP login grant with an active relay address
**When** the user deactivates the relay address
**Then** the relay hard-bounces but the RP login grant remains active

### Requirement: REQ-005 Per-address rate limiting and aggregate-only volume

The system SHALL rate-limit inbound mail per relay address and MUST expose per-RP
volume only as aggregate counts — never message contents or per-sender tracking.

#### Scenario: Aggregate-only volume

**Given** a relay address that received several messages
**When** the user views per-RP email volume
**Then** only an aggregate count is shown (e.g. "12 emails this week"), with no message contents or sender-level tracking
