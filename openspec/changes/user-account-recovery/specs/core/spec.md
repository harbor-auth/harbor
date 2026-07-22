# Spec: User account recovery (fail-closed Phase 1)

Adds single-use, salted-hash recovery codes and fallback authenticators for
passkey users who lose their devices, behind a fail-closed ceremony that keeps
the account `recovery_required` until a fresh passkey is enrolled. Recovery is
rate-limited, region-pinned, metered aggregate-only, and audited. Social/M-of-N
recovery is out of scope.

## ADDED Requirements

### Requirement: REQ-001 Single-use, salted-hash recovery codes

The system SHALL persist recovery codes only as salted SHA-256 hashes in a
`recovery_codes` table, show each plaintext code to the user exactly once, and
NEVER persist the plaintext. Each code MUST be single-use: consuming a code is
atomic and a consumed or unknown code MUST be rejected.

#### Scenario: Only a hash is stored

**Given** recovery codes are generated for a user
**When** the `recovery_codes` rows are inspected
**Then** each row holds a salted hash and no plaintext code is present

#### Scenario: A code is single-use

**Given** a valid unused recovery code
**When** it is consumed a second time
**Then** the second attempt is rejected and grants nothing

### Requirement: REQ-002 Fallback authenticators

The system SHALL allow a user to register additional passkeys and a hardware
security key via the shipped WebAuthn path as independent recovery factors, so
losing one authenticator does not lock the account.

#### Scenario: A second authenticator recovers the account

**Given** a user with two registered passkeys who loses one
**When** the user authenticates with the remaining passkey
**Then** the user regains access without needing a recovery code

### Requirement: REQ-003 Fail-closed ceremony keeps recovery_required until a fresh factor

The system SHALL, on a successful recovery via code or fallback factor,
re-establish an authenticated session but keep the account `recovery_required`
until the user enrolls a fresh passkey; only then is the guard cleared.

#### Scenario: Account stays gated until a fresh passkey is enrolled

**Given** a user who recovers using a recovery code
**When** the recovery session is established
**Then** the account remains `recovery_required` until a new passkey is enrolled, after which the guard is cleared

#### Scenario: Invalid code grants nothing

**Given** an invalid or exhausted recovery code
**When** it is presented
**Then** the ceremony fails closed and no session is granted

### Requirement: REQ-004 Rate-limited, audited, region-pinned, no enumeration

The system SHALL rate-limit recovery attempts, pin them to the user's region,
meter them aggregate-only, and emit `user-audit-trail` events for begin /
success / failure. Recovery endpoints MUST NOT reveal whether a given user or
code exists, and no code MUST satisfy a different user.

#### Scenario: Recovery attempts are audited

**Given** a recovery attempt (success or failure)
**When** the attempt completes
**Then** a corresponding `auth.recovery_*` event is recorded in the user's audit trail

#### Scenario: No cross-user code

**Given** a recovery code belonging to user `A`
**When** user `B` presents it
**Then** it does not satisfy `B`'s recovery
