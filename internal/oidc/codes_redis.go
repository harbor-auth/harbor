package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Compile-time check that RedisAuthCodeStore implements AuthCodeStore.
var _ AuthCodeStore = (*RedisAuthCodeStore)(nil)

// RedisAuthCodeStore is a Redis-backed AuthCodeStore for multi-replica safety.
// It retains consumed code bindings through the replay window and uses a marker for
// reuse detection (docs/DESIGN.md §4.4).
type RedisAuthCodeStore struct {
	client  *redis.Client
	codeTTL time.Duration
}

// NewRedisAuthCodeStore creates a Redis-backed auth code store.
// codeTTL controls how long codes live before expiring (typically 60s).
func NewRedisAuthCodeStore(client *redis.Client, codeTTL time.Duration) *RedisAuthCodeStore {
	return &RedisAuthCodeStore{
		client:  client,
		codeTTL: codeTTL,
	}
}

// codeKey returns the Redis key for the auth code data.
func codeKey(code string) string {
	return "authcode:" + code
}

// consumedKey returns the Redis key for the consumed marker.
func consumedKey(code string) string {
	return "authcode:consumed:" + code
}

// Save implements AuthCodeStore. It stores the auth code with NX (only if
// not exists) and EX (expiration). Returns an error if the code already exists.
func (s *RedisAuthCodeStore) Save(ctx context.Context, code AuthCode) error {
	data, err := json.Marshal(code)
	if err != nil {
		return fmt.Errorf("marshal auth code: %w", err)
	}

	// SET NX EX: set only if not exists, with expiration
	ok, err := s.client.SetNX(ctx, codeKey(code.Code), data, s.codeTTL).Result()
	if err != nil {
		return fmt.Errorf("redis SET NX: %w", err)
	}
	if !ok {
		return fmt.Errorf("auth code already exists")
	}
	return nil
}

// Peek implements AuthCodeStore. It reads the stored code and its consumed
// state without mutating it. MGET observes code and replay metadata atomically.
func (s *RedisAuthCodeStore) Peek(ctx context.Context, code string) (AuthCode, bool, bool, error) {
	values, err := s.client.MGet(ctx, consumedKey(code), codeKey(code)).Result()
	if err != nil {
		return AuthCode{}, false, false, fmt.Errorf("redis MGET: %w", err)
	}
	consumed := values[0] != nil
	value := values[1]
	if value == nil {
		return AuthCode{}, false, false, nil
	}
	data, ok := value.(string)
	if !ok {
		return AuthCode{}, false, false, fmt.Errorf("unexpected auth code data type")
	}

	var stored AuthCode
	if err := json.Unmarshal([]byte(data), &stored); err != nil {
		return AuthCode{}, false, false, fmt.Errorf("unmarshal auth code: %w", err)
	}

	return stored, true, consumed, nil
}

// consumeScript is a Lua script for atomic check-and-mark consumption.
// It returns:
//   - 0 if the code was not found
//   - 1 if this is the first use (code consumed successfully)
//   - 2 if the code was already consumed (reuse detected)
//
// KEYS[1] = code key, KEYS[2] = consumed marker key
// ARGV[1] = consumed marker TTL in seconds
var consumeScript = redis.NewScript(`
local code_data = redis.call('GET', KEYS[1])
if not code_data then
    return {0, nil}
end
if redis.call('EXISTS', KEYS[2]) == 1 then
    return {2, code_data}
end

-- Retain consumed binding metadata after the fresh code expires.
redis.call('SET', KEYS[2], '1', 'EX', ARGV[1])
redis.call('EXPIRE', KEYS[1], ARGV[1])
return {1, code_data}
`)

// Consume implements AuthCodeStore with reuse detection. It uses a Lua
// script for atomic check-and-mark: the first call returns ConsumeFirstUse and
// retains the binding and consumed marker for the replay window. Replays do not
// extend retention. The service separately rejects expired unspent codes.
func (s *RedisAuthCodeStore) Consume(ctx context.Context, code string) (ConsumeResult, error) {
	// Consumed marker TTL = 2x code TTL for reliable reuse detection
	consumedTTL := int(s.codeTTL.Seconds() * 2)
	if consumedTTL < 1 {
		consumedTTL = 1
	}

	result, err := consumeScript.Run(ctx, s.client,
		[]string{codeKey(code), consumedKey(code)},
		consumedTTL,
	).Slice()
	if err != nil {
		return ConsumeResult{}, fmt.Errorf("redis consume script: %w", err)
	}

	status := int(result[0].(int64))
	switch status {
	case 0:
		return ConsumeResult{Status: ConsumeNotFound}, nil
	case 1, 2:
		data, ok := result[1].(string)
		if !ok {
			return ConsumeResult{}, fmt.Errorf("unexpected code data type")
		}
		var stored AuthCode
		if err := json.Unmarshal([]byte(data), &stored); err != nil {
			return ConsumeResult{}, fmt.Errorf("unmarshal auth code: %w", err)
		}
		if status == 1 {
			return ConsumeResult{Status: ConsumeFirstUse, Code: stored}, nil
		}
		return ConsumeResult{Status: ConsumeReused, Code: stored}, nil
	default:
		return ConsumeResult{}, fmt.Errorf("unexpected consume status: %d", status)
	}
}
