// This file implements the one-time SSO login code Harbor Cloud's SAML
// bridge redeems on behalf of an end user (POST /admin/v1/user-sessions
// mints it; GET /login/sso in cmd/harbor-mgmt consumes it).
package cloudapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// loginCodeTTL bounds a minted SSO login code's lifetime. It crosses exactly
// one redirect (Harbor Cloud's SAML bridge -> the browser -> GET
// /login/sso?code=) — any longer would leave a live bearer credential
// sitting in browser history and proxy access logs for no operational
// benefit.
const loginCodeTTL = 120 * time.Second

// loginCodeBytes is the CSPRNG size, in bytes, of a minted login code before
// base64url encoding (256 bits).
const loginCodeBytes = 32

// LoginCode is the state a minted login code resolves to.
type LoginCode struct {
	UserID      string
	NamespaceID string
	IssuedAt    time.Time
}

// ErrLoginCodeNotFound is returned when a login code is unknown, already
// consumed, or expired. Callers (cmd/harbor-mgmt's GET /login/sso) must
// never distinguish these three cases in their response: GETDEL already
// makes "consumed" and "unknown" indistinguishable at the store layer, and
// Redis's own TTL eviction makes "expired" indistinguishable from "unknown"
// too — collapsing all three into one generic error is what keeps the
// handler from leaking which case applied.
var ErrLoginCodeNotFound = errors.New("cloudapi: login code not found")

// LoginCodeStore issues and consumes one-time SSO login codes.
// Implementations must make Consume atomically single-use across every
// harbor-mgmt replica.
type LoginCodeStore interface {
	// Issue mints a fresh, single-use login code bound to code's state,
	// returning the opaque bearer code. code.IssuedAt is recorded as given
	// (the caller supplies "now" so tests can control it).
	Issue(ctx context.Context, code LoginCode) (string, error)

	// Consume atomically retrieves and deletes the state for the presented
	// code, so a second Consume with the same code always fails
	// (ErrLoginCodeNotFound) — the anti-replay property GET /login/sso
	// relies on.
	Consume(ctx context.Context, code string) (LoginCode, error)
}

// loginCodeKeyPrefix namespaces login-code records in the shared Redis
// keyspace. Keys are built from the code's SHA-256 HASH, never the code
// itself — the same reasoning as BFFSessionRecord.BrowserNonceHash
// (docs/plans/fix-bff-session-binding.md): a Redis dump (backup, replication
// snapshot, `KEYS`/`SCAN` under a misconfigured ACL) then yields no live,
// redeemable credential, only an opaque digest.
const loginCodeKeyPrefix = "sso_login_code:"

func loginCodeKey(code string) string {
	sum := sha256.Sum256([]byte(code))
	return loginCodeKeyPrefix + hex.EncodeToString(sum[:])
}

// loginCodeRecord is the JSON value stored at the code's hashed key.
type loginCodeRecord struct {
	UserID      string    `json:"user_id"`
	NamespaceID string    `json:"namespace_id"`
	IssuedAt    time.Time `json:"issued_at"`
}

// RedisLoginCodeStore is a Redis-backed LoginCodeStore.
type RedisLoginCodeStore struct {
	client *redis.Client
}

// Compile-time proof that RedisLoginCodeStore implements LoginCodeStore.
var _ LoginCodeStore = (*RedisLoginCodeStore)(nil)

// NewRedisLoginCodeStore builds a RedisLoginCodeStore over an existing Redis
// client.
func NewRedisLoginCodeStore(client *redis.Client) *RedisLoginCodeStore {
	return &RedisLoginCodeStore{client: client}
}

// Issue implements LoginCodeStore. The code is 256 bits of CSPRNG output,
// unpadded base64url-encoded (the same alphabet cloudapi/sessions.go's
// randSessionToken uses) — collision-resistant enough that a SETNX loss is
// treated as an infrastructure error, never silently retried under the same
// code.
func (s *RedisLoginCodeStore) Issue(ctx context.Context, code LoginCode) (string, error) {
	raw := make([]byte, loginCodeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("cloudapi: generate login code: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(raw)

	data, err := json.Marshal(loginCodeRecord(code))
	if err != nil {
		return "", fmt.Errorf("cloudapi: marshal login code: %w", err)
	}

	ok, err := s.client.SetNX(ctx, loginCodeKey(plaintext), data, loginCodeTTL).Result()
	if err != nil {
		return "", fmt.Errorf("cloudapi: redis SET NX login code: %w", err)
	}
	if !ok {
		// A SHA-256 collision on 256 fresh CSPRNG bits is not a condition
		// worth retrying — surface it as an infrastructure failure.
		return "", errors.New("cloudapi: login code hash collision")
	}
	return plaintext, nil
}

// Consume implements LoginCodeStore via GETDEL — the same atomic
// retrieve-and-delete primitive internal/bff/session_redis.go's
// RedisBFFSessionStore.Consume uses, making single-use enforcement race-free
// across every harbor-mgmt replica: two concurrent redemptions of the same
// code can never both succeed.
func (s *RedisLoginCodeStore) Consume(ctx context.Context, code string) (LoginCode, error) {
	data, err := s.client.GetDel(ctx, loginCodeKey(code)).Bytes()
	if errors.Is(err, redis.Nil) {
		return LoginCode{}, ErrLoginCodeNotFound
	}
	if err != nil {
		return LoginCode{}, fmt.Errorf("cloudapi: redis GETDEL login code: %w", err)
	}
	var rec loginCodeRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return LoginCode{}, fmt.Errorf("cloudapi: unmarshal login code: %w", err)
	}
	return LoginCode(rec), nil
}
