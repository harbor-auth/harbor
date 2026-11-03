package clients

import (
	"time"

	"github.com/harbor-auth/harbor/internal/oidc"
	"github.com/redis/go-redis/v9"
)

// RedisAuthCodeStore is the shared Redis implementation of the OIDC code store.
type RedisAuthCodeStore = oidc.RedisAuthCodeStore

// NewRedisAuthCodeStore creates the production Redis authorization-code store.
func NewRedisAuthCodeStore(client *redis.Client, codeTTL time.Duration) *RedisAuthCodeStore {
	return oidc.NewRedisAuthCodeStore(client, codeTTL)
}
