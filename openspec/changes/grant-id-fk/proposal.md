# Proposal: Add grant_id foreign key to sessions table

## Problem

`RefreshSession.GrantID` is always empty string today. The `buildCreateSessionParams`
function in `internal/clients/sessions.go` has a `TODO(grant-fk)` comment documenting
that it silently drops any non-empty GrantID. Without this FK, revocation cannot be
scoped to a specific user-client-grant family — revoking one app access risks
over-revoking (all sessions for user-client) or under-revoking (only current session).

Per DESIGN §3.5 and §11.3, each refresh token family MUST be tied to a specific grant
so that grant revocation cascades correctly to all associated sessions.

## Proposed Solution

1. Add migration `0006_grant_id_fk` to add `grant_id UUID` column to sessions table
   with a foreign key to grants(id).
2. Update `buildCreateSessionParams` to populate `grant_id` from `RefreshSession.GrantID`.
3. Add `RevokeSessionsByGrant(grantID)` method to revoke all sessions for a grant.
4. Update `issueRefreshToken` in service.go to populate `GrantID` from the grant.
5. Ensure rotation copies `GrantID` to the new session.

## Non-Goals

- Automatic cascade deletion (handled by explicit revocation calls).
- Backfilling existing sessions (new sessions only; old sessions will have NULL grant_id).
- UI for grant management (separate feature).

## Success Criteria

- [ ] Sessions table has `grant_id` FK column.
- [ ] New sessions are created with correct `grant_id`.
- [ ] `RevokeSessionsByGrant` revokes only sessions for the specified grant.
- [ ] Refresh token rotation preserves `GrantID`.
- [ ] `make agent-check` clean.
