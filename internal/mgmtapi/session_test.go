package mgmtapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestEnrollmentSession_SaveAndGet(t *testing.T) {
	s := NewInMemoryEnrollmentSessionStore()
	key, err := NewEnrollmentSessionKey()
	if err != nil {
		t.Fatalf("NewEnrollmentSessionKey: %v", err)
	}
	want := []byte("user-handle-bytes")
	if err := s.Save(context.Background(), key, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.UserHandle(context.Background(), key)
	if err != nil {
		t.Fatalf("UserHandle: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("handle = %q, want %q", got, want)
	}
}

func TestEnrollmentSession_NotFound(t *testing.T) {
	s := NewInMemoryEnrollmentSessionStore()
	if _, err := s.UserHandle(context.Background(), "nope"); !errors.Is(err, ErrEnrollmentSessionNotFound) {
		t.Fatalf("err = %v, want ErrEnrollmentSessionNotFound", err)
	}
}

func TestEnrollmentSession_Expiry(t *testing.T) {
	s := NewInMemoryEnrollmentSessionStore()
	now := time.Now()
	s.now = func() time.Time { return now }
	const key = "k"
	if err := s.Save(context.Background(), key, []byte("h")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Advance past TTL: the entry must now read as absent.
	s.now = func() time.Time { return now.Add(enrollmentSessionTTL + time.Second) }
	if _, err := s.UserHandle(context.Background(), key); !errors.Is(err, ErrEnrollmentSessionNotFound) {
		t.Fatalf("err = %v, want ErrEnrollmentSessionNotFound after expiry", err)
	}
}

func TestEnrollmentSession_SaveCopiesSlice(t *testing.T) {
	s := NewInMemoryEnrollmentSessionStore()
	handle := []byte{1, 2, 3}
	if err := s.Save(context.Background(), "k", handle); err != nil {
		t.Fatalf("Save: %v", err)
	}
	handle[0] = 9 // mutate caller's slice after Save
	got, err := s.UserHandle(context.Background(), "k")
	if err != nil {
		t.Fatalf("UserHandle: %v", err)
	}
	if got[0] != 1 {
		t.Fatalf("stored handle was aliased to caller slice: got[0]=%d, want 1", got[0])
	}
}

func TestEnrollmentSessionKey_Unique(t *testing.T) {
	a, err := NewEnrollmentSessionKey()
	if err != nil {
		t.Fatalf("key a: %v", err)
	}
	b, err := NewEnrollmentSessionKey()
	if err != nil {
		t.Fatalf("key b: %v", err)
	}
	if a == "" || a == b {
		t.Fatalf("keys must be non-empty and unique: %q %q", a, b)
	}
}

// TestRedisEnrollmentSessionStore_CrossReplica proves the enrollment handoff
// is durable across management replicas. POST /enroll may land on replica A
// while WebAuthn register/begin lands on replica B; both must resolve the same
// opaque session through Redis, without process-local fallback state.
func TestRedisEnrollmentSessionStore_CrossReplica(t *testing.T) {
	mr := miniredis.RunT(t)
	clientA := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	clientB := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		_ = clientA.Close() //nolint:errcheck // test cleanup
		_ = clientB.Close() //nolint:errcheck // test cleanup
	})

	replicaA := NewRedisEnrollmentSessionStore(clientA)
	replicaB := NewRedisEnrollmentSessionStore(clientB)
	const key = "cross-replica-enrollment"
	want := []byte("user-handle-from-replica-a")

	if err := replicaA.Save(context.Background(), key, want); err != nil {
		t.Fatalf("replica A Save: %v", err)
	}
	got, err := replicaB.UserHandle(context.Background(), key)
	if err != nil {
		t.Fatalf("replica B UserHandle: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("replica B handle = %q, want %q", got, want)
	}
	// register/begin and register/finish both resolve the handoff. Reading from
	// replica B must not consume it before the second operation.
	gotAgain, err := replicaA.UserHandle(context.Background(), key)
	if err != nil {
		t.Fatalf("replica A second UserHandle: %v", err)
	}
	if string(gotAgain) != string(want) {
		t.Fatalf("replica A second handle = %q, want %q", gotAgain, want)
	}
}

func TestRedisEnrollmentSessionStore_ExpiresFailClosed(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // test cleanup
	store := NewRedisEnrollmentSessionStore(client)

	if err := store.Save(context.Background(), "expired", []byte("user")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	mr.FastForward(enrollmentSessionTTL + time.Second)
	if _, err := store.UserHandle(context.Background(), "expired"); !errors.Is(err, ErrEnrollmentSessionNotFound) {
		t.Fatalf("UserHandle(expired) = %v, want ErrEnrollmentSessionNotFound", err)
	}
}
