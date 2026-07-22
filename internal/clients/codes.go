package clients

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/harbor-auth/harbor/internal/oidc"
	"github.com/redis/go-redis/v9"
)

// Compile-time check that RedisAuthCodeStore implements oidc.AuthCodeStore.
var _ oidc.AuthCodeStore = (*RedisAuthCodeStore)(nil)

// RedisAuthCodeStore is a Redis-backed AuthCodeStore for multi-replica safety.
// It stores auth codes with TTL-based expiry and uses a consumed marker for
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

// Save implements oidc.AuthCodeStore. It stores the auth code with NX (only if
// not exists) and EX (expiration). Returns an error if the code already exists.
func (s *RedisAuthCodeStore) Save(ctx context.Context, code oidc.AuthCode) error {
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

// Peek implements oidc.AuthCodeStore. It reads the stored code and its consumed
// state without mutating it, using a pipeline for efficiency.
func (s *RedisAuthCodeStore) Peek(ctx context.Context, code string) (oidc.AuthCode, bool, bool, error) {
	pipe := s.client.Pipeline()
	getCmd := pipe.Get(ctx, codeKey(code))
	existsCmd := pipe.Exists(ctx, consumedKey(code))
	_, err := pipe.Exec(ctx)
	// Pipeline exec error is only fatal if it's not a key-not-found scenario.
	// Individual command errors are checked below.
	if err != nil && !errors.Is(err, redis.Nil) {
		return oidc.AuthCode{}, false, false, fmt.Errorf("redis pipeline: %w", err)
	}

	// Check if code exists
	data, err := getCmd.Result()
	if errors.Is(err, redis.Nil) {
		return oidc.AuthCode{}, false, false, nil
	}
	if err != nil {
		return oidc.AuthCode{}, false, false, fmt.Errorf("redis GET: %w", err)
	}

	var stored oidc.AuthCode
	if err := json.Unmarshal([]byte(data), &stored); err != nil {
		return oidc.AuthCode{}, false, false, fmt.Errorf("unmarshal auth code: %w", err)
	}

	// Check consumed marker
	consumed := existsCmd.Val() > 0

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

local already_consumed = redis.call('EXISTS', KEYS[2])
if already_consumed == 1 then
    return {2, code_data}
end

-- Mark as consumed with TTL = 2x code TTL for reliable reuse detection
redis.call('SET', KEYS[2], '1', 'EX', ARGV[1])
return {1, code_data}
`)

// Consume implements oidc.AuthCodeStore with reuse detection. It uses a Lua
// script for atomic check-and-mark: the first call returns ConsumeFirstUse and
// sets the consumed marker; any later call returns ConsumeReused.
func (s *RedisAuthCodeStore) Consume(ctx context.Context, code string) (oidc.ConsumeResult, error) {
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
		return oidc.ConsumeResult{}, fmt.Errorf("redis consume script: %w", err)
	}

	status := int(result[0].(int64))
	switch status {
	case 0:
		return oidc.ConsumeResult{Status: oidc.ConsumeNotFound}, nil
	case 1, 2:
		data, ok := result[1].(string)
		if !ok {
			return oidc.ConsumeResult{}, fmt.Errorf("unexpected code data type")
		}
		var stored oidc.AuthCode
		if err := json.Unmarshal([]byte(data), &stored); err != nil {
			return oidc.ConsumeResult{}, fmt.Errorf("unmarshal auth code: %w", err)
		}
		if status == 1 {
			return oidc.ConsumeResult{Status: oidc.ConsumeFirstUse, Code: stored}, nil
		}
		return oidc.ConsumeResult{Status: oidc.ConsumeReused, Code: stored}, nil
	default:
		return oidc.ConsumeResult{}, fmt.Errorf("unexpected consume status: %d", status)
	}
}
