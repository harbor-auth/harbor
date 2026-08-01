package mgmtapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/redis/go-redis/v9"
)

const enrollmentSessionPrefix = "harbor:mgmt:enrollment:"
const recoveryCeremonyPrefix = "harbor:mgmt:recovery:"

// RedisEnrollmentSessionStore shares the enrollment-to-WebAuthn handoff
// between management replicas.
type RedisEnrollmentSessionStore struct {
	client *redis.Client
}

func NewRedisEnrollmentSessionStore(client *redis.Client) *RedisEnrollmentSessionStore {
	if client == nil {
		panic("mgmtapi.NewRedisEnrollmentSessionStore: client must not be nil")
	}
	return &RedisEnrollmentSessionStore{client: client}
}

func (s *RedisEnrollmentSessionStore) Save(ctx context.Context, key string, userHandle []byte) error {
	value := base64.RawURLEncoding.EncodeToString(userHandle)
	return s.client.Set(ctx, enrollmentSessionPrefix+key, value, enrollmentSessionTTL).Err()
}

func (s *RedisEnrollmentSessionStore) UserHandle(ctx context.Context, key string) ([]byte, error) {
	value, err := s.client.Get(ctx, enrollmentSessionPrefix+key).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrEnrollmentSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	handle, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, ErrEnrollmentSessionNotFound
	}
	return handle, nil
}

// RedisRecoveryCeremonyStore shares recovery ceremonies between replicas.
type RedisRecoveryCeremonyStore struct {
	client *redis.Client
}

type redisRecoveryCeremony struct {
	UserID string `json:"user_id"`
	Region string `json:"region"`
}

func NewRedisRecoveryCeremonyStore(client *redis.Client) *RedisRecoveryCeremonyStore {
	if client == nil {
		panic("mgmtapi.NewRedisRecoveryCeremonyStore: client must not be nil")
	}
	return &RedisRecoveryCeremonyStore{client: client}
}

func (s *RedisRecoveryCeremonyStore) Save(ctx context.Context, requestID, userID, region string) error {
	value, err := json.Marshal(redisRecoveryCeremony{UserID: userID, Region: region})
	if err != nil {
		return err
	}
	return s.client.Set(ctx, recoveryCeremonyPrefix+requestID, value, recoveryCeremonyTTL).Err()
}

func (s *RedisRecoveryCeremonyStore) Lookup(ctx context.Context, requestID string) (string, string, error) {
	value, err := s.client.Get(ctx, recoveryCeremonyPrefix+requestID).Bytes()
	if errors.Is(err, redis.Nil) {
		return "", "", ErrRecoveryCeremonyNotFound
	}
	if err != nil {
		return "", "", err
	}
	var ceremony redisRecoveryCeremony
	if err := json.Unmarshal(value, &ceremony); err != nil {
		return "", "", ErrRecoveryCeremonyNotFound
	}
	return ceremony.UserID, ceremony.Region, nil
}

func (s *RedisRecoveryCeremonyStore) Delete(ctx context.Context, requestID string) error {
	return s.client.Del(ctx, recoveryCeremonyPrefix+requestID).Err()
}
