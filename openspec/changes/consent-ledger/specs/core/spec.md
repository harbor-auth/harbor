# Spec: Consent ledger (per-user / per-RP / per-scope consent grants)

Persists per-(user, client) consent grants with a granted scope set and enforces
them at `/authorize`, exposes user-facing list/revoke on `harbor-mgmt`, and
emits a consent event taxonomy for the user audit trail. Defines the data model,
the skip-vs-prompt enforcement decision (including OIDC `prompt` handling), the
revocation cascade, the emitted events, and the no-leakage / regional
invariants.

## ADDED Requirements

### Requirement: REQ-001 Persisted per-(user, client) consent grant

The system SHALL persist consent as a `consent_grants` row keyed uniquely by
`(user_id, client_id)`, carrying the canonical granted scope set, `granted_at`,
`updated_at`, and a nullable `revoked_at`, holding no PII beyond the FKs and the
scope strings.

#### Scenario: Approving consent upserts a grant

**Given** a user approves an authorization request for client `C` with scopes `{openid, email}`
**When** the consent ceremony completes
**Then** a `consent_grants` row for `(user, C)` exists with the canonical scope set `{email, openid}`

#### Scenario: One grant per (user, client)

**Given** an existing grant for `(user, C)`
**When** a further approval for `(user, C)` is recorded
**Then** the existing row is updated (upsert), not duplicated

### Requirement: REQ-002 Authorize skips a covering grant, re-prompts otherwise

The system SHALL, at `/authorize`, **skip** the consent ceremony when a
non-revoked grant's scope set is a superset of the requested scopes, and MUST
**re-prompt** when there is no grant, when the requested scopes escalate
(requested ⊄ granted), or when the grant is revoked. On approval after a prompt
it MUST upsert the (possibly widened) scope set.

#### Scenario: Covering grant skips the prompt

**Given** a non-revoked grant for `(user, C)` with scopes `{openid, email}`
**When** the user authorizes `C` requesting `{openid}`
**Then** the consent prompt is skipped

#### Scenario: Scope escalation re-prompts and widens

**Given** a grant for `(user, C)` with scopes `{openid}`
**When** the user authorizes `C` requesting `{openid, email}`
**Then** the consent prompt is shown
**And** on approval the grant's scope set becomes `{email, openid}`

#### Scenario: Revoked grant re-prompts

**Given** a grant for `(user, C)` whose `revoked_at` is set
**When** the user authorizes `C`
**Then** it is treated as no grant and the consent prompt is shown

### Requirement: REQ-003 OIDC prompt parameter is honoured

The system SHALL force the consent ceremony when `prompt=consent` is present
even if a covering grant exists, and MUST return an OIDC error when
`prompt=none` is present and consent would otherwise be required.

#### Scenario: prompt=consent forces re-consent

**Given** a covering non-revoked grant for `(user, C)`
**When** the user authorizes `C` with `prompt=consent`
**Then** the consent prompt is shown despite the covering grant

#### Scenario: prompt=none errors when consent is required

**Given** no covering grant for `(user, C)`
**When** an authorization request arrives with `prompt=none`
**Then** the flow returns an OIDC error rather than prompting

### Requirement: REQ-004 User list/revoke with RP-token cascade

The system SHALL provide user-authenticated `harbor-mgmt` endpoints for a user
to list **their own** consent grants and revoke one. Revocation MUST set
`revoked_at` and cascade a token/session revocation for that RP via the shipped
revocation stack.

#### Scenario: Revoke sets revoked_at and logs the RP out

**Given** a user with an active grant for client `C`
**When** the user revokes that grant via harbor-mgmt
**Then** the grant's `revoked_at` is set
**And** the RP's outstanding tokens/session for that user are revoked

#### Scenario: A user sees only their own grants

**Given** grants belonging to user `A` and user `B`
**When** user `A` lists consent grants
**Then** only `A`'s grants are returned

### Requirement: REQ-005 Consent event emission for the audit trail

The system SHALL emit a structured consent event through a seam the user audit
trail can consume for each grant, scope escalation, and revocation:
`consent.granted`, `consent.scope_escalated`, `consent.revoked`.

#### Scenario: Granting emits consent.granted

**Given** a new consent grant is recorded for `(user, C)`
**When** the upsert completes
**Then** a `consent.granted` event is emitted through the audit seam

#### Scenario: Revoking emits consent.revoked

**Given** a user revokes a consent grant for `(user, C)`
**When** `revoked_at` is set
**Then** a `consent.revoked` event is emitted through the audit seam

### Requirement: REQ-006 No cross-client satisfaction, regional storage

The system SHALL satisfy a request's consent only from a grant whose
`client_id` matches the requesting client, and MUST store consent regionally
with no cross-region consent lookup.

#### Scenario: A grant does not satisfy a different client

**Given** a grant for `(user, C1)`
**When** the user authorizes a different client `C2`
**Then** the `C1` grant does not skip the prompt for `C2`
