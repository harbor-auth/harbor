# Spec: Refresh token rotation

Adds opaque, one-time-use refresh tokens backed by a `SessionStore`, with atomic rotation and reuse-as-theft detection. Defines the session contract, the token-response additions, the rotation flow, and the hash-at-rest and atomicity invariants.

## ADDED Requirements

### Requirement: REQ-001 SessionStore contract

The system SHALL provide a SessionStore for session lifecycle management.

The system MUST provide a `SessionStore` for creating, looking up by refresh-token hash, and revoking sessions (individually and per-user). Every session carries region.

```go
package oidc

type SessionStore interface {
    CreateSession(ctx context.Context, s Session) (Session, error)
    GetActiveSession(ctx context.Context, refreshTokenHash []byte) (Session, bool, error)
    RevokeSession(ctx context.Context, sessionID string) error
    RevokeSessionsByUser(ctx context.Context, userID string) error
}

type Session struct {
    ID, Region, UserID, ClientID, DeviceLabel string
    RefreshTokenHash []byte
    ExpiresAt time.Time
}
```

#### Scenario: Create and look up an active session

**Given** a session created with a refresh-token hash  
**When** `GetActiveSession` is called with that hash  
**Then** the active session is returned with `found = true`

#### Scenario: Region populated on session

**Given** a session being created  
**When** `CreateSession` executes  
**Then** the `Region` field is populated on the stored row

### Requirement: REQ-002 Opaque refresh token in token response

The system SHALL return opaque refresh tokens and store only their hash.

The token response MUST gain `refresh_token` (opaque CSPRNG plaintext, returned once only) and `refresh_token_expires_in`, and the OpenAPI spec MUST be updated. Refresh tokens are never JWTs; only their SHA-256 hash is stored, never plaintext in DB, logs, or telemetry. No refresh token is issued when `offline_access` is not in scopes.

#### Scenario: Refresh token returned once

**Given** a token request whose scopes include `offline_access`  
**When** the token response is built  
**Then** it includes an opaque `refresh_token` and `refresh_token_expires_in`, and only the SHA-256 hash is persisted

#### Scenario: Hash at rest only

**Given** a refresh token is issued  
**When** it is persisted or logged  
**Then** only the SHA-256 hash is stored and no plaintext appears in DB, logs, or telemetry

#### Scenario: No offline_access means no refresh token

**Given** a token request whose scopes do not include `offline_access`  
**When** the token response is built  
**Then** no refresh token is returned

### Requirement: REQ-003 Atomic one-time-use rotation

The system SHALL rotate refresh tokens atomically with one-time use.

On refresh, the presented token MUST be hashed and looked up. A not-found or expired session yields `invalid_grant`. On success, the old session MUST be revoked and a new session created in a single database transaction, then fresh access/ID tokens plus a new refresh token are issued.

Rotation flow: `Hash(presented)` → `GetActiveSession` (not found/expired ⇒ `invalid_grant`; found-but-revoked ⇒ theft signal + `RevokeSessionsByUser` + `invalid_grant`); then `RevokeSession(old)` + `CreateSession(new)` in one transaction; then issue fresh access/ID tokens + new refresh token.

#### Scenario: Successful rotation

**Given** a valid, active, unexpired refresh token  
**When** it is presented for rotation  
**Then** the old session is revoked and a new session created in one transaction, and fresh access/ID tokens plus a new refresh token are issued

#### Scenario: One-time use

**Given** a refresh token that was already used once  
**When** it is presented again  
**Then** it is no longer active because it was revoked on first use

#### Scenario: Transaction failure mid-rotation

**Given** the revoke-old + create-new transaction fails  
**When** rotation is attempted  
**Then** an error is returned and no new token is issued

### Requirement: REQ-004 Reuse detection as theft signal

The system SHALL treat refresh-token reuse as theft and revoke the session family.

Presenting a revoked (already-used) refresh token MUST be treated as theft: the system emits a theft signal, revokes the entire session family via `RevokeSessionsByUser`, and returns `invalid_grant`.

#### Scenario: Not found or expired token

**Given** a presented refresh token whose hash is not found or is expired  
**When** rotation is attempted  
**Then** the request is rejected with `invalid_grant`

#### Scenario: Reuse triggers family revocation

**Given** a presented refresh token that maps to a revoked session  
**When** rotation is attempted  
**Then** a theft signal is emitted, `RevokeSessionsByUser` revokes the family, and `invalid_grant` is returned
