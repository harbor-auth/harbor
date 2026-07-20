# Design: Add grant_id foreign key to sessions table

## Key Decisions

### Decision 1: Nullable FK for backward compatibility
**Chosen:** Add `grant_id` as nullable initially; existing sessions will have NULL.
**Rationale:** Zero-downtime migration; new sessions get proper grant_id, old sessions
continue to work with user-client scoped revocation.
**Alternatives considered:** NOT NULL with default (requires backfill, rejected for
complexity).

### Decision 2: Populate GrantID at token issuance, not rotation
**Chosen:** Set `rs.GrantID = grant.ID` in `issueRefreshToken`; rotation copies it.
**Rationale:** The grant is already recovered for region lookup at issuance time;
copying during rotation preserves the lineage without re-querying.
**Alternatives considered:** Re-query grant at rotation (unnecessary DB call, rejected).

### Decision 3: RevokeSessionsByGrant as separate method
**Chosen:** Add `RevokeSessionsByGrant(ctx, grantID)` alongside existing
`RevokeSessionsByUserClient`.
**Rationale:** More precise revocation scope (§11.3); keeps existing user-client
revocation for theft-signal family revoke intact.
**Alternatives considered:** Modify RevokeSessionsByUserClient to accept optional
grantID (muddies semantics, rejected).

### Decision 4: Fail closed on invalid GrantID
**Chosen:** `buildCreateSessionParams` returns error if GrantID is non-empty but
invalid UUID.
**Rationale:** Fail-closed principle (§11.7); a malformed GrantID indicates a bug
that must be caught early.
**Alternatives considered:** Silently accept empty string as NULL (unsafe, rejected).

### Decision 5: No cascade delete, explicit revocation
**Chosen:** No `ON DELETE CASCADE`; grant revocation explicitly calls
`RevokeSessionsByGrant`.
**Rationale:** Explicit control over revocation timing; cascade could cause
unexpected mass logout during grant cleanup.
