# Spec: Compliance export & erasure (DSAR)

Adds a user-authenticated, region-pinned DSAR flow: EXPORT assembles the
caller's own decrypted data into a portable, region-pinned, short-lived bundle
with no operator plaintext path; ERASE crypto-shreds by destroying the user's
wrapped DEK so their envelope-encrypted PII is permanently, provably
unrecoverable and a prior export cannot re-hydrate it. Realises §11.5 via §11.6.

## ADDED Requirements

### Requirement: REQ-001 Caller-scoped export bundle, no operator plaintext path

The system SHALL, on a data-subject export request, assemble the **caller's own
decrypted** data (profile, consent grants, audit-trail events, relay mappings)
into a portable bundle, decrypting only under the caller's DEK. It MUST NOT
expose any cross-user read or operator plaintext path.

#### Scenario: Export returns only the caller's data

**Given** an authenticated user requesting their export
**When** the bundle is assembled
**Then** it contains only that user's own decrypted data and no other user's data is readable

#### Scenario: No operator plaintext path

**Given** an operator without the user's DEK
**When** an export is assembled
**Then** there is no path by which the operator obtains the user's plaintext

### Requirement: REQ-002 Region-pinned, DEK-encrypted, short-lived bundle

The system SHALL keep the export bundle region-pinned and short-lived; it MUST
NOT be cached cross-region or retained after delivery. The bundle itself is PII
at rest and therefore MUST be encrypted under the **caller's own DEK** with a
short TTL — there is no operator-readable plaintext bundle at rest. Because the
bundle is DEK-encrypted, a later crypto-shred (REQ-003) that destroys the
user's wrapped DEK renders an un-downloaded bundle permanently unrecoverable.

#### Scenario: Bundle is DEK-encrypted, in-region, and expires

**Given** an `eu` user's export bundle
**When** the bundle is produced
**Then** it is encrypted under the caller's DEK, region-pinned to `eu`, short-lived, and is not retained (as operator-readable plaintext) after delivery

#### Scenario: A later erase kills an un-downloaded bundle

**Given** a DEK-encrypted export bundle that was produced but never downloaded
**When** the user is subsequently erased (crypto-shred destroys `users.dek_wrapped`)
**Then** the un-downloaded bundle can no longer be decrypted and is permanently unrecoverable

### Requirement: REQ-003 Crypto-shred erasure is permanent and provable

The system SHALL, on a data-subject erasure request, crypto-shred the user by
destroying `users.dek_wrapped`, rendering all their envelope-encrypted PII
permanently unrecoverable. A prior export bundle MUST NOT be usable to re-hydrate
erased data, and the erasure MUST be irreversible.

#### Scenario: PII is unrecoverable after erase

**Given** a user with envelope-encrypted PII
**When** the user is erased (crypto-shred destroys `users.dek_wrapped`)
**Then** their envelope-encrypted PII is permanently unrecoverable

#### Scenario: A prior export cannot re-hydrate erased data

**Given** an export bundle produced before erasure
**When** the user has since been erased
**Then** the erased data cannot be re-hydrated into the system from the bundle

### Requirement: REQ-005 Crypto-shred survival set contains no recoverable PII

Erasure crypto-shreds the user's DEK, so everything decryptable only under that
DEK becomes unrecoverable. The system SHALL guarantee that whatever **survives**
an erase contains **no recoverable PII**:

- Recovery `code_hash` rows (derived from user secrets) MUST be deleted on erase.
- Audit-trail rows keyed by a **pseudonymous** `user_id` may survive as
  pseudonymous references; any free-text / PII fields on them MUST be
  envelope-encrypted under the user DEK so they shred with it.
- Consent-ledger rows may survive only as pseudonymous references (no plaintext
  PII).

#### Scenario: Nothing recoverable-PII survives an erase

**Given** an erased user
**When** the surviving rows (audit-trail, consent-ledger, any recovery bookkeeping) are inspected
**Then** recovery `code_hash` rows are gone, surviving rows carry only a pseudonymous `user_id`, and any free-text/PII fields on them are unrecoverable (shredded with the DEK)

### Requirement: REQ-004 Export & erase are region-pinned, metered, and audited

The system SHALL require authentication for export and erase, pin both to the
user's region, meter them aggregate-only, and emit `user-audit-trail` events for
each.

#### Scenario: Erase is audited

**Given** an authenticated erasure request
**When** the erasure completes
**Then** a `compliance.erase_*` event is recorded in the user's audit trail and only aggregate metrics are emitted
