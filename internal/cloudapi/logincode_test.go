package cloudapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestLoginCodeStore(t *testing.T) (*RedisLoginCodeStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // test cleanup
	return NewRedisLoginCodeStore(client), mr
}

func TestLoginCodeIssueThenConsume(t *testing.T) {
	store, _ := newTestLoginCodeStore(t)
	issuedAt := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	code, err := store.Issue(context.Background(), LoginCode{UserID: "user-1", NamespaceID: "acme", IssuedAt: issuedAt})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if code == "" {
		t.Fatal("Issue returned an empty code")
	}

	got, err := store.Consume(context.Background(), code)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.UserID != "user-1" || got.NamespaceID != "acme" || !got.IssuedAt.Equal(issuedAt) {
		t.Fatalf("Consume() = %+v, want UserID=user-1 NamespaceID=acme IssuedAt=%v", got, issuedAt)
	}
}

// TestLoginCodeSingleUse proves the anti-replay property GET /login/sso
// relies on: a second Consume of the same code always fails.
func TestLoginCodeSingleUse(t *testing.T) {
	store, _ := newTestLoginCodeStore(t)
	code, err := store.Issue(context.Background(), LoginCode{UserID: "user-1", NamespaceID: "acme", IssuedAt: time.Now()})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if _, err := store.Consume(context.Background(), code); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if _, err := store.Consume(context.Background(), code); !errors.Is(err, ErrLoginCodeNotFound) {
		t.Fatalf("second Consume error = %v, want ErrLoginCodeNotFound", err)
	}
}

func TestLoginCodeUnknownCodeNotFound(t *testing.T) {
	store, _ := newTestLoginCodeStore(t)
	if _, err := store.Consume(context.Background(), "never-issued-code"); !errors.Is(err, ErrLoginCodeNotFound) {
		t.Fatalf("Consume(unknown) error = %v, want ErrLoginCodeNotFound", err)
	}
}

// TestLoginCodeExpires proves the TTL is enforced: a code that has aged out
// in the backing store is indistinguishable from an unknown one.
func TestLoginCodeExpires(t *testing.T) {
	store, mr := newTestLoginCodeStore(t)
	code, err := store.Issue(context.Background(), LoginCode{UserID: "user-1", NamespaceID: "acme", IssuedAt: time.Now()})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	mr.FastForward(loginCodeTTL + time.Second)

	if _, err := store.Consume(context.Background(), code); !errors.Is(err, ErrLoginCodeNotFound) {
		t.Fatalf("Consume(expired) error = %v, want ErrLoginCodeNotFound", err)
	}
}

// TestLoginCodeTTLIsSetOnIssue proves the Redis key actually carries the
// documented 120s TTL, not an unbounded/forgotten one.
func TestLoginCodeTTLIsSetOnIssue(t *testing.T) {
	store, mr := newTestLoginCodeStore(t)
	code, err := store.Issue(context.Background(), LoginCode{UserID: "user-1", NamespaceID: "acme", IssuedAt: time.Now()})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	ttl := mr.TTL(loginCodeKey(code))
	if ttl <= 0 || ttl > loginCodeTTL {
		t.Fatalf("Redis key TTL = %v, want (0, %v]", ttl, loginCodeTTL)
	}
}

// TestLoginCodeRedisKeyIsHashNotCode proves the Redis key is derived from
// the code's SHA-256 hash, never the plaintext code — so a Redis dump
// (backup, replication snapshot, KEYS/SCAN under a misconfigured ACL) yields
// no live, redeemable credential.
func TestLoginCodeRedisKeyIsHashNotCode(t *testing.T) {
	store, mr := newTestLoginCodeStore(t)
	code, err := store.Issue(context.Background(), LoginCode{UserID: "user-1", NamespaceID: "acme", IssuedAt: time.Now()})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// The plaintext code itself must never appear as a key.
	if mr.Exists(loginCodeKeyPrefix + code) {
		t.Fatal("Redis key is keyed on the plaintext code, not its hash")
	}

	sum := sha256.Sum256([]byte(code))
	wantKey := loginCodeKeyPrefix + hex.EncodeToString(sum[:])
	if !mr.Exists(wantKey) {
		t.Fatalf("expected key %q (hash of code) to exist", wantKey)
	}
}

// TestLoginCodeIssueIsCollisionResistant proves two issued codes for
// different state are never identical (256 bits of fresh CSPRNG per call).
func TestLoginCodeIssueIsCollisionResistant(t *testing.T) {
	store, _ := newTestLoginCodeStore(t)
	a, err := store.Issue(context.Background(), LoginCode{UserID: "user-1", NamespaceID: "acme", IssuedAt: time.Now()})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	b, err := store.Issue(context.Background(), LoginCode{UserID: "user-2", NamespaceID: "acme", IssuedAt: time.Now()})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if a == b {
		t.Fatal("two Issue calls produced the same code")
	}
}
