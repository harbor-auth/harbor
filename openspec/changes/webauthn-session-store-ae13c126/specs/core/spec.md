# Spec: WebAuthn session persistence

Implements `RedisSessionStore` for WebAuthn ceremony challenges, replacing `InMemorySessionStore` for multi-replica safety. The store uses `SET NX EX` (5-min TTL) for saves and Lua atomic `GET+DEL` for one-time-use semantics. Defines the store contract, atomicity invariants, and TTL-based expiry behaviour.

## ADDED Requirements

### Requirement: REQ-001 RedisSessionStore contract

The system SHALL provide a RedisSessionStore that implements the SessionStore interface.

The system MUST provide a `RedisSessionStore` that implements `webauthn.SessionStore` with `Save` and `Take` methods. The store wraps a Redis client and a configurable session TTL.

```go
package webauthn

type RedisSessionStore struct{}

func NewRedisSessionStore(client *redis.Client, sessionTTL time.Duration) *RedisSessionStore

func (s *RedisSessionStore) Save(ctx context.Context, key string, data gowebauthn.SessionData) error
func (s *RedisSessionStore) Take(ctx context.Context, key string) (gowebauthn.SessionData, error)
```

#### Scenario: Save and Take round-trip preserves SessionData

**Given** a `gowebauthn.SessionData` struct with Challenge, UserID, AllowedCredentialIDs, and UserVerification fields
**When** `Save` is called followed by `Take`
**Then** the returned SessionData equals the original with all fields intact

#### Scenario: RedisSessionStore satisfies SessionStore interface

**Given** a `RedisSessionStore` instance
**When** assigned to a variable of type `SessionStore`
**Then** the assignment compiles (compile-time interface assertion)

### Requirement: REQ-002 Race-safe Save with SET NX EX

The system SHALL use SET NX EX for race-safe session storage.

`Save` MUST JSON-marshal the `gowebauthn.SessionData` and store it via `SET NX EX <ttl>` keyed by `webauthn_session:<key>`. The `NX` flag MUST prevent a duplicate Begin call from overwriting an in-flight challenge. Save MUST return an error if the key already exists.

#### Scenario: Save succeeds for new key

**Given** a key that does not exist in Redis
**When** `Save` is called
**Then** the session is stored with the configured TTL and no error is returned

#### Scenario: Save fails for duplicate key

**Given** a key that already exists in Redis (concurrent Begin race)
**When** `Save` is called with the same key
**Then** `ErrSessionExists` is returned indicating the key already exists

#### Scenario: Save uses configured TTL

**Given** a RedisSessionStore with a 5-minute TTL
**When** `Save` stores a session
**Then** the Redis key expires after 5 minutes

### Requirement: REQ-003 Atomic one-time-use Take via Lua

The system SHALL use a Lua script for atomic GET+DEL on Take.

`Take` MUST use a Lua script that atomically `GET`s the key, `DEL`s the key, and returns the value. Two concurrent `Take` calls for the same session MUST NOT both succeed — only the first wins. `Take` MUST return `ErrSessionNotFound` when the key is absent, already taken, or expired.

```lua
local data = redis.call('GET', KEYS[1])
if not data then
    return nil
end
redis.call('DEL', KEYS[1])
return data
```

#### Scenario: Take returns session and deletes it

**Given** a session stored via `Save`
**When** `Take` is called
**Then** the session is returned and the Redis key is deleted

#### Scenario: Double-Take returns ErrSessionNotFound

**Given** a session that was already taken once
**When** `Take` is called a second time
**Then** `ErrSessionNotFound` is returned

#### Scenario: Expired session returns ErrSessionNotFound

**Given** a session whose TTL has elapsed
**When** `Take` is called
**Then** `ErrSessionNotFound` is returned (Redis auto-expired the key)

#### Scenario: Concurrent Take calls serialize atomically

**Given** two goroutines calling `Take` for the same session simultaneously
**When** both calls execute
**Then** exactly one succeeds and the other returns `ErrSessionNotFound`

### Requirement: REQ-004 JSON round-trip fidelity

The system SHALL preserve all SessionData fields through JSON serialization.

All fields of `gowebauthn.SessionData` (Challenge, UserID, AllowedCredentialIDs, Expires, UserVerification, RelyingPartyID) MUST survive a JSON marshal/unmarshal round-trip. The implementation MUST verify compatibility with the pinned `go-webauthn/webauthn` version in `go.mod`.

#### Scenario: Challenge bytes preserved

**Given** a SessionData with a 32-byte Challenge
**When** the session is saved and taken
**Then** the Challenge bytes are identical

#### Scenario: AllowedCredentialIDs preserved

**Given** a SessionData with multiple AllowedCredentialIDs
**When** the session is saved and taken
**Then** all credential IDs are preserved in order

### Requirement: REQ-005 Dev fallback to InMemorySessionStore

The system SHALL fall back to InMemorySessionStore when REDIS_URL is unset.

When `REDIS_URL` is unset, `cmd/harbor-mgmt` MUST wire `InMemorySessionStore` for local development. The `InMemorySessionStore` production-warning comment MUST reference the `webauthn-session-store` plan slug.

#### Scenario: Redis available uses RedisSessionStore

**Given** `REDIS_URL` is set to a valid Redis instance
**When** `harbor-mgmt` starts
**Then** `RedisSessionStore` is wired for WebAuthn ceremonies

#### Scenario: No Redis uses InMemorySessionStore

**Given** `REDIS_URL` is unset
**When** `harbor-mgmt` starts
**Then** `InMemorySessionStore` is wired with a log warning

### Requirement: REQ-006 No PII in Redis keys or values

The system SHALL store no PII in Redis.

Redis keys and values MUST NOT contain PII. `gowebauthn.SessionData` contains only the challenge nonce, allowed credential IDs, RPID, and verification flags — no user email or name. The opaque session key is a 256-bit CSPRNG value, not a user identifier.

#### Scenario: SessionData contains no PII

**Given** the `gowebauthn.SessionData` struct
**When** its fields are enumerated
**Then** no field contains user email, name, or other PII

#### Scenario: Session key is opaque

**Given** a session key derived from the BFF `request_id`
**When** the key is stored in Redis
**Then** the key prefix is `webauthn_session:` followed by an opaque 256-bit value
