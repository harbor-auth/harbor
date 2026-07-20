# Spec: Grant ID Foreign Key for Sessions

## ADDED Requirements

### REQ-GRANT-FK-001: Sessions table MUST have grant_id column
The `sessions` table SHALL have a `grant_id UUID` column that references
`grants(id)`. The column SHALL be nullable for backward compatibility with
existing sessions.

**Scenario:**
- Given: A new session is created during token exchange
- When: The session is persisted to the database
- Then: The `grant_id` column contains the UUID of the associated grant

### REQ-GRANT-FK-002: RefreshSession MUST carry GrantID
The `RefreshSession` struct SHALL include a `GrantID` field that is populated
at token issuance from `grant.ID`.

**Scenario:**
- Given: A user completes authorization and consent
- When: `issueRefreshToken` creates a new RefreshSession
- Then: `rs.GrantID` equals the grant's UUID

### REQ-GRANT-FK-003: Token rotation MUST preserve GrantID
When a refresh token is rotated, the new session MUST copy the `GrantID` from
the old session.

**Scenario:**
- Given: A refresh token with GrantID "abc-123" is used
- When: The token is rotated to create a new session
- Then: The new session has GrantID "abc-123"

### REQ-GRANT-FK-004: RevokeSessionsByGrant MUST revoke only matching sessions
The `RevokeSessionsByGrant(ctx, grantID)` method SHALL revoke all sessions
with the specified `grant_id` and MUST NOT revoke sessions with different
`grant_id` values.

**Scenario:**
- Given: Sessions S1, S2 with grant_id "G1" and S3 with grant_id "G2"
- When: `RevokeSessionsByGrant(ctx, "G1")` is called
- Then: S1 and S2 are revoked; S3 remains active

### REQ-GRANT-FK-005: Invalid GrantID MUST fail closed
If `buildCreateSessionParams` receives a non-empty but invalid UUID in
`GrantID`, it MUST return an error. NEVER silently accept malformed input.

**Scenario:**
- Given: A RefreshSession with GrantID "not-a-uuid"
- When: `buildCreateSessionParams` is called
- Then: An error is returned; no session is created

## Go Interface Stubs

```go
// SessionStore extends with grant-scoped revocation.
type SessionStore interface {
    // ... existing methods ...
    
    // RevokeSessionsByGrant revokes all sessions for the given grant.
    RevokeSessionsByGrant(ctx context.Context, grantID string) error
}
```

## Security Invariants

- **INV-REFRESH-GRANT-ID-PROPAGATED**: Every RefreshSession created via
  `issueRefreshToken` MUST have a non-empty `GrantID` equal to the associated
  grant's UUID. Rotation MUST preserve this value.

- **INV-GRANT-REVOCATION-SCOPED**: `RevokeSessionsByGrant` MUST revoke exactly
  the sessions matching the specified grant_id — no more, no fewer.
