package webauthn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
)

// Compile-time check that RedisSessionStore implements SessionStore.
var _ SessionStore = (*RedisSessionStore)(nil)

// ErrSessionExists is returned when Save is called with a key that already
// exists (NX guard failed). This prevents a second Begin call from overwriting
// an in-flight challenge (race-safe, docs/plans/webauthn-session-store.md).
var ErrSessionExists = fmt.Errorf("webauthn: session already exists")

// RedisSessionStore is a Redis-backed SessionStore for multi-replica safety.
// It stores WebAuthn ceremony sessions with TTL-based expiry (5 min default)
// and JSON encoding (docs/plans/webauthn-session-store.md).
type RedisSessionStore struct {
	client     *redis.Client
	sessionTTL time.Duration
}

// NewRedisSessionStore creates a Redis-backed WebAuthn session store.
// sessionTTL controls how long sessions live before expiring (typically 5 min).
func NewRedisSessionStore(client *redis.Client, sessionTTL time.Duration) *RedisSessionStore {
	return &RedisSessionStore{
		client:     client,
		sessionTTL: sessionTTL,
	}
}

// sessionKey returns the Redis key for the WebAuthn session data.
func sessionKey(key string) string {
	return "webauthn_session:" + key
}

// Save implements SessionStore. It stores the session record with NX (only if
// not exists) and EX (expiration). Returns ErrSessionExists if a session with
// the same key already exists (race-safe).
func (s *RedisSessionStore) Save(ctx context.Context, key string, data gowebauthn.SessionData) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal webauthn session: %w", err)
	}

	// SET NX EX: set only if not exists, with expiration
	ok, err := s.client.SetNX(ctx, sessionKey(key), jsonData, s.sessionTTL).Result()
	if err != nil {
		return fmt.Errorf("redis SET NX: %w", err)
	}
	if !ok {
		return ErrSessionExists
	}
	return nil
}

// takeScript is a Lua script for atomic GET+DEL (one-time-use semantics).
// It returns nil if the key does not exist; otherwise returns the value and
// deletes the key atomically. Two concurrent Take calls cannot both succeed.
//
// KEYS[1] = session key
var takeScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then
    return nil
end
redis.call('DEL', KEYS[1])
return data
`)

// Take implements SessionStore: returns and deletes the session (one-time use).
// Returns ErrSessionNotFound if the key is absent or already taken.
func (s *RedisSessionStore) Take(ctx context.Context, key string) (gowebauthn.SessionData, error) {
	result, err := takeScript.Run(ctx, s.client, []string{sessionKey(key)}).Result()
	if errors.Is(err, redis.Nil) || result == nil {
		return gowebauthn.SessionData{}, ErrSessionNotFound
	}
	if err != nil {
		return gowebauthn.SessionData{}, fmt.Errorf("redis take script: %w", err)
	}

	jsonData, ok := result.(string)
	if !ok {
		return gowebauthn.SessionData{}, fmt.Errorf("redis take: unexpected result type %T", result)
	}

	var data gowebauthn.SessionData
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		return gowebauthn.SessionData{}, fmt.Errorf("unmarshal webauthn session: %w", err)
	}

	return data, nil
}
