# Spec: User audit trail (user-owned, envelope-encrypted, crypto-shredded)

Adds a user-owned, envelope-encrypted audit trail built on the shipped per-user
DEK primitive. Defines the data model and encrypted payload, the closed event
taxonomy, best-effort non-blocking emission, the user-only decrypted read path
(no operator plaintext), and crypto-shred erasure of the trail.

## ADDED Requirements

### Requirement: REQ-001 Envelope-encrypted event payload under the user's DEK

The system SHALL persist each audit event as a `user_audit_events` row carrying
`user_id`, a coarse `event_type`, `created_at`, and a `payload` encrypted under
the **user's DEK** via the shipped `Encryptor`. The stored payload MUST be
ciphertext; the plaintext detail MUST NOT be stored in the clear.

#### Scenario: Recorded payload is ciphertext

**Given** an audit event recorded for a user with detail `{client: C, scopes: [openid]}`
**When** the `user_audit_events` row is inspected directly
**Then** the `payload` column is ciphertext and does not contain the plaintext detail

#### Scenario: Operator sees only coarse metadata

**Given** stored audit events
**When** the operator reads the table directly
**Then** only `user_id`, `event_type`, and `created_at` are legible — never the payload detail

### Requirement: REQ-002 Closed event taxonomy

The system SHALL record only a closed set of `event_type`s — `auth.login`,
`token.issued`, `token.refreshed`, `token.revoked` — plus the `consent.*` events
defined by `consent-ledger` (`consent.granted`, `consent.scope_escalated`,
`consent.revoked`).

#### Scenario: A login records auth.login

**Given** a user completes a login
**When** the audit trail is written
**Then** an `auth.login` event is recorded for that user

#### Scenario: A consent grant records consent.granted

**Given** the consent ledger emits a `consent.granted` event for a user
**When** the audit recorder consumes it
**Then** a `consent.granted` event is recorded in that user's trail

### Requirement: REQ-003 Best-effort, non-blocking emission

The system SHALL emit audit events best-effort: a failure to write an audit
event MUST be logged and metered but MUST NOT break or fail the originating
auth/token/consent flow.

#### Scenario: Audit-write failure does not break login

**Given** the audit store is unavailable
**When** a user completes a login that would emit `auth.login`
**Then** the login succeeds
**And** the audit-write failure is logged and metered rather than surfaced to the user

### Requirement: REQ-004 User-only decrypted read path

The system SHALL provide a user-authenticated `harbor-mgmt` endpoint that lists
**the caller's own** events, decrypting each `payload` under the caller's DEK.
A user MUST NOT be able to read another user's trail, and there MUST be no
operator plaintext read path.

#### Scenario: Owner reads their decrypted trail

**Given** a user with recorded audit events
**When** the user lists their audit trail via harbor-mgmt
**Then** the events are returned with their payloads decrypted under the user's DEK

#### Scenario: A user cannot read another user's trail

**Given** audit events for users `A` and `B`
**When** user `A` requests the trail
**Then** only `A`'s events are returned and `B`'s are never exposed

### Requirement: REQ-005 Crypto-shred renders the trail unrecoverable

The system SHALL ensure that destroying a user's wrapped DEK
(`users.dek_wrapped`) renders that user's audit payloads permanently
unrecoverable, consistent with the §11.6 crypto-shred erasure model.

#### Scenario: Trail is unreadable after the wrapped DEK is destroyed

**Given** a user with recorded, DEK-encrypted audit events
**When** the user's `users.dek_wrapped` is destroyed (crypto-shred)
**Then** the user's audit payloads can no longer be decrypted by anyone
