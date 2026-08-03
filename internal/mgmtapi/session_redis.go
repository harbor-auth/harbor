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

// redisEnrollmentSession is the JSON envelope stored under an enrollment
// session key. Recovery is carried alongside the handle so register/finish
// can tell a lost-device recovery session apart from first-time enrollment
// without a second round trip.
type redisEnrollmentSession struct {
	Handle   string `json:"h"`
	Recovery bool   `json:"r,omitempty"`
}

func (s *RedisEnrollmentSessionStore) Save(ctx context.Context, key string, userHandle []byte, recovery bool) error {
	value, err := json.Marshal(redisEnrollmentSession{
		Handle:   base64.RawURLEncoding.EncodeToString(userHandle),
		Recovery: recovery,
	})
	if err != nil {
		return err
	}
	return s.client.Set(ctx, enrollmentSessionPrefix+key, value, enrollmentSessionTTL).Err()
}

func (s *RedisEnrollmentSessionStore) UserHandle(ctx context.Context, key string) ([]byte, bool, error) {
	value, err := s.client.Get(ctx, enrollmentSessionPrefix+key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false, ErrEnrollmentSessionNotFound
	}
	if err != nil {
		return nil, false, err
	}
	var session redisEnrollmentSession
	if err := json.Unmarshal(value, &session); err != nil {
		return nil, false, ErrEnrollmentSessionNotFound
	}
	handle, err := base64.RawURLEncoding.DecodeString(session.Handle)
	if err != nil {
		return nil, false, ErrEnrollmentSessionNotFound
	}
	return handle, session.Recovery, nil
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
