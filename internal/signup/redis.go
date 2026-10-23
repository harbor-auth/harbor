package signup

import (
	"context"
	"github.com/redis/go-redis/v9"
	"time"
)

type RedisChallenges struct{ client *redis.Client }

func NewRedisChallenges(client *redis.Client) *RedisChallenges { return &RedisChallenges{client} }

const challengePrefix = "harbor:signup:challenge:"

func (s *RedisChallenges) Save(ctx context.Context, key, proof string, payload []byte) error {
	_, err := s.client.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, challengePrefix+key, "proof", proof, "payload", payload, "attempts", 0)
		p.Expire(ctx, challengePrefix+key, TTL)
		return nil
	})
	return err
}

var consumeScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return '' end
local attempts = redis.call('HINCRBY', KEYS[1], 'attempts', 1)
if redis.call('HGET', KEYS[1], 'proof') == ARGV[1] then
 local payload = redis.call('HGET', KEYS[1], 'payload')
 redis.call('DEL', KEYS[1])
 return payload
end
if attempts >= 5 then redis.call('DEL', KEYS[1]) end
return ''
`)

func (s *RedisChallenges) Consume(ctx context.Context, key, proof string) ([]byte, error) {
	value, err := consumeScript.Run(ctx, s.client, []string{challengePrefix + key}, proof).Text()
	if err != nil {
		return nil, err
	}
	if value == "" {
		return nil, ErrInvalidCode
	}
	return []byte(value), nil
}

var destinationScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return count
`)

func (s *RedisChallenges) AllowDestination(ctx context.Context, key string) (bool, error) {
	n, err := destinationScript.Run(ctx, s.client, []string{"harbor:signup:destination:" + key}, (time.Hour).Milliseconds()).Int64()
	return n <= 5, err
}
