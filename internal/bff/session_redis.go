package bff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Compile-time check that RedisBFFSessionStore implements BFFSessionStore.
var _ BFFSessionStore = (*RedisBFFSessionStore)(nil)

// RedisBFFSessionStore is a Redis-backed BFFSessionStore for multi-replica
// safety. It stores BFF session records with TTL-based expiry (5 min default)
// and JSON encoding (docs/plans/bff-session-middleware.md).
type RedisBFFSessionStore struct {
	client     *redis.Client
	sessionTTL time.Duration
}

// NewRedisBFFSessionStore creates a Redis-backed BFF session store.
// sessionTTL controls how long sessions live before expiring (typically 5 min).
func NewRedisBFFSessionStore(client *redis.Client, sessionTTL time.Duration) *RedisBFFSessionStore {
	return &RedisBFFSessionStore{
		client:     client,
		sessionTTL: sessionTTL,
	}
}

// sessionKey returns the Redis key for the BFF session data.
func sessionKey(requestID string) string {
	return "bff_session:" + requestID
}

// Create implements BFFSessionStore. It stores the session record with NX (only
// if not exists) and EX (expiration). Returns an error if a session with the
// same RequestID already exists.
func (s *RedisBFFSessionStore) Create(ctx context.Context, record BFFSessionRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal bff session: %w", err)
	}

	// SET NX EX: set only if not exists, with expiration
	ok, err := s.client.SetNX(ctx, sessionKey(record.RequestID), data, s.sessionTTL).Result()
	if err != nil {
		return fmt.Errorf("redis SET NX: %w", err)
	}
	if !ok {
		return fmt.Errorf("bff: session already exists")
	}
	return nil
}

// Get implements BFFSessionStore. It retrieves the session record by RequestID.
// Returns ErrBFFSessionNotFound if no such session exists. Expiry is handled by
// Redis TTL, so ErrBFFSessionExpired is not returned (expired keys are absent).
func (s *RedisBFFSessionStore) Get(ctx context.Context, requestID string) (BFFSessionRecord, error) {
	data, err := s.client.Get(ctx, sessionKey(requestID)).Result()
	if errors.Is(err, redis.Nil) {
		return BFFSessionRecord{}, ErrBFFSessionNotFound
	}
	if err != nil {
		return BFFSessionRecord{}, fmt.Errorf("redis GET: %w", err)
	}

	var record BFFSessionRecord
	if err := json.Unmarshal([]byte(data), &record); err != nil {
		return BFFSessionRecord{}, fmt.Errorf("unmarshal bff session: %w", err)
	}

	// Double-check ExpiresAt in case the record was created with a shorter TTL
	// than the Redis key TTL (defensive; should not happen in normal operation).
	if time.Now().After(record.ExpiresAt) {
		// Delete the stale key (best-effort — the key expires via Redis TTL anyway).
		_ = s.client.Del(ctx, sessionKey(requestID)).Err() //nolint:errcheck // best-effort cleanup; key expires via Redis TTL anyway
		return BFFSessionRecord{}, ErrBFFSessionExpired
	}

	return record, nil
}

// setUserScript is a Lua script for atomic get-modify-set of the UserID field.
// It returns:
//   - 0 if the session was not found
//   - 1 if the UserID was set successfully
//
// KEYS[1] = session key
// ARGV[1] = userID to set
var setUserScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then
    return 0
end

local record = cjson.decode(data)
record.UserID = ARGV[1]
local ttl = redis.call('TTL', KEYS[1])
if ttl > 0 then
    redis.call('SET', KEYS[1], cjson.encode(record), 'EX', ttl)
else
    redis.call('SET', KEYS[1], cjson.encode(record))
end
return 1
`)

// setUserWithRecoveryScript is a Lua script for atomic get-modify-set of
// UserID, RecoveryRequired, and SessionScope fields.
// It returns:
//   - 0 if the session was not found
//   - 1 if the fields were set successfully
//
// KEYS[1] = session key
// ARGV[1] = userID to set
// ARGV[2] = recoveryRequired ("true" or "false")
// ARGV[3] = sessionScope ("full" or "enrollment_only")
var setUserWithRecoveryScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then
    return 0
end

local record = cjson.decode(data)
record.UserID = ARGV[1]
record.RecoveryRequired = (ARGV[2] == "true")
record.SessionScope = ARGV[3]
local ttl = redis.call('TTL', KEYS[1])
if ttl > 0 then
    redis.call('SET', KEYS[1], cjson.encode(record), 'EX', ttl)
else
    redis.call('SET', KEYS[1], cjson.encode(record))
end
return 1
`)

// setMFAVerifiedScript is a Lua script for atomic get-modify-set of the
// MFAVerifiedAt field, preserving the remaining TTL.
// It returns:
//   - 0 if the session was not found
//   - 1 if the field was set successfully
//
// KEYS[1] = session key
// ARGV[1] = MFAVerifiedAt as an RFC3339Nano timestamp string
var setMFAVerifiedScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then
    return 0
end

local record = cjson.decode(data)
record.MFAVerifiedAt = ARGV[1]
local ttl = redis.call('TTL', KEYS[1])
if ttl > 0 then
    redis.call('SET', KEYS[1], cjson.encode(record), 'EX', ttl)
else
    redis.call('SET', KEYS[1], cjson.encode(record))
end
return 1
`)

// SetUser implements BFFSessionStore. It atomically updates the UserID field of
// an existing session using a Lua script to preserve the remaining TTL.
func (s *RedisBFFSessionStore) SetUser(ctx context.Context, requestID string, userID string) error {
	result, err := setUserScript.Run(ctx, s.client,
		[]string{sessionKey(requestID)},
		userID,
	).Int()
	if err != nil {
		return fmt.Errorf("redis setuser script: %w", err)
	}

	if result == 0 {
		return ErrBFFSessionNotFound
	}
	return nil
}

// SetUserWithRecoveryStatus implements BFFSessionStore. It atomically updates
// the UserID, RecoveryRequired, and SessionScope fields using a Lua script.
func (s *RedisBFFSessionStore) SetUserWithRecoveryStatus(ctx context.Context, requestID, userID string, recoveryRequired bool) error {
	recoveryStr := "false"
	scope := string(SessionScopeFull)
	if recoveryRequired {
		recoveryStr = "true"
		scope = string(SessionScopeEnrollmentOnly)
	}

	result, err := setUserWithRecoveryScript.Run(ctx, s.client,
		[]string{sessionKey(requestID)},
		userID,
		recoveryStr,
		scope,
	).Int()
	if err != nil {
		return fmt.Errorf("redis setuser-recovery script: %w", err)
	}

	if result == 0 {
		return ErrBFFSessionNotFound
	}
	return nil
}

// SetMFAVerified implements BFFSessionStore. It atomically stamps the session
// with a step-up verification time using a Lua script to preserve the remaining
// TTL. The timestamp is stored in RFC3339Nano form so it round-trips through
// Go's time.Time JSON (un)marshaling.
func (s *RedisBFFSessionStore) SetMFAVerified(ctx context.Context, requestID string, verifiedAt time.Time) error {
	result, err := setMFAVerifiedScript.Run(ctx, s.client,
		[]string{sessionKey(requestID)},
		verifiedAt.UTC().Format(time.RFC3339Nano),
	).Int()
	if err != nil {
		return fmt.Errorf("redis setmfaverified script: %w", err)
	}

	if result == 0 {
		return ErrBFFSessionNotFound
	}
	return nil
}

// Delete implements BFFSessionStore. It removes the session record. This is a
// no-op if the session does not exist (consistent with the interface contract).
func (s *RedisBFFSessionStore) Delete(ctx context.Context, requestID string) error {
	if err := s.client.Del(ctx, sessionKey(requestID)).Err(); err != nil {
		return fmt.Errorf("redis DEL: %w", err)
	}
	return nil
}
