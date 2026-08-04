package mgmtapi

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

type enrollmentEntry struct {
	userHandle []byte
	recovery   bool
	returnTo   string
	expires    time.Time
}

type InMemoryEnrollmentSessionStore struct {
	mu       sync.Mutex
	sessions map[string]enrollmentEntry
	ttl      time.Duration
	now      func() time.Time
}

func NewInMemoryEnrollmentSessionStore() *InMemoryEnrollmentSessionStore {
	return &InMemoryEnrollmentSessionStore{
		sessions: make(map[string]enrollmentEntry),
		ttl:      enrollmentSessionTTL,
		now:      time.Now,
	}
}

func (s *InMemoryEnrollmentSessionStore) Save(_ context.Context, key string, userHandle []byte, recovery bool, returnTo string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := append([]byte(nil), userHandle...)
	s.sessions[key] = enrollmentEntry{userHandle: h, recovery: recovery, returnTo: returnTo, expires: s.now().Add(s.ttl)}
	return nil
}

func (s *InMemoryEnrollmentSessionStore) UserHandle(_ context.Context, key string) ([]byte, bool, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[key]
	if !ok {
		return nil, false, "", ErrEnrollmentSessionNotFound
	}
	if s.now().After(entry.expires) {
		delete(s.sessions, key)
		return nil, false, "", ErrEnrollmentSessionNotFound
	}
	return entry.userHandle, entry.recovery, entry.returnTo, nil
}

func TestEnrollmentSession_SaveAndGet(t *testing.T) {
	s := NewInMemoryEnrollmentSessionStore()
	key, err := NewEnrollmentSessionKey()
	if err != nil {
		t.Fatalf("NewEnrollmentSessionKey: %v", err)
	}
	want := []byte("user-handle-bytes")
	if err := s.Save(context.Background(), key, want, false, ""); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, recovery, returnTo, err := s.UserHandle(context.Background(), key)
	if err != nil {
		t.Fatalf("UserHandle: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("handle = %q, want %q", got, want)
	}
	if recovery {
		t.Fatal("recovery = true, want false for a first-time enrollment session")
	}
	if returnTo != "" {
		t.Fatalf("returnTo = %q, want empty when Save was not given one", returnTo)
	}
}

// TestEnrollmentSession_RecoveryFlagRoundTrips proves a session Saved with
// recovery=true reports recovery=true from UserHandle — the signal
// webauthn.Handler.FinishRegistration needs to route a lost-device recovery
// ceremony to svc.FinishRecoveryRegistration instead of svc.FinishRegistration.
func TestEnrollmentSession_RecoveryFlagRoundTrips(t *testing.T) {
	s := NewInMemoryEnrollmentSessionStore()
	key, err := NewEnrollmentSessionKey()
	if err != nil {
		t.Fatalf("NewEnrollmentSessionKey: %v", err)
	}
	want := []byte("recovering-user-handle")
	if err := s.Save(context.Background(), key, want, true, ""); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, recovery, _, err := s.UserHandle(context.Background(), key)
	if err != nil {
		t.Fatalf("UserHandle: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("handle = %q, want %q", got, want)
	}
	if !recovery {
		t.Fatal("recovery = false, want true for a recovery session")
	}
}

// TestEnrollmentSession_ReturnToRoundTrips proves a session Saved with a
// return_to value reports it back unchanged from UserHandle — the carrier
// wirePostRegistrationHandoff (cmd/harbor-mgmt/caller.go) reads to copy
// return_to onto the BFF session it issues (design.md Decision 5 / REQ-004).
func TestEnrollmentSession_ReturnToRoundTrips(t *testing.T) {
	s := NewInMemoryEnrollmentSessionStore()
	key, err := NewEnrollmentSessionKey()
	if err != nil {
		t.Fatalf("NewEnrollmentSessionKey: %v", err)
	}
	if err := s.Save(context.Background(), key, []byte("user-handle"), false, "/dashboard/after-signup"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	_, _, returnTo, err := s.UserHandle(context.Background(), key)
	if err != nil {
		t.Fatalf("UserHandle: %v", err)
	}
	if returnTo != "/dashboard/after-signup" {
		t.Fatalf("returnTo = %q, want %q", returnTo, "/dashboard/after-signup")
	}
}

func TestEnrollmentSession_NotFound(t *testing.T) {
	s := NewInMemoryEnrollmentSessionStore()
	if _, _, _, err := s.UserHandle(context.Background(), "nope"); !errors.Is(err, ErrEnrollmentSessionNotFound) {
		t.Fatalf("err = %v, want ErrEnrollmentSessionNotFound", err)
	}
}

func TestEnrollmentSession_Expiry(t *testing.T) {
	s := NewInMemoryEnrollmentSessionStore()
	now := time.Now()
	s.now = func() time.Time { return now }
	const key = "k"
	if err := s.Save(context.Background(), key, []byte("h"), false, ""); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Advance past TTL: the entry must now read as absent.
	s.now = func() time.Time { return now.Add(enrollmentSessionTTL + time.Second) }
	if _, _, _, err := s.UserHandle(context.Background(), key); !errors.Is(err, ErrEnrollmentSessionNotFound) {
		t.Fatalf("err = %v, want ErrEnrollmentSessionNotFound after expiry", err)
	}
}

func TestEnrollmentSession_SaveCopiesSlice(t *testing.T) {
	s := NewInMemoryEnrollmentSessionStore()
	handle := []byte{1, 2, 3}
	if err := s.Save(context.Background(), "k", handle, false, ""); err != nil {
		t.Fatalf("Save: %v", err)
	}
	handle[0] = 9 // mutate caller's slice after Save
	got, _, _, err := s.UserHandle(context.Background(), "k")
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

	if err := replicaA.Save(context.Background(), key, want, false, ""); err != nil {
		t.Fatalf("replica A Save: %v", err)
	}
	got, recovery, _, err := replicaB.UserHandle(context.Background(), key)
	if err != nil {
		t.Fatalf("replica B UserHandle: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("replica B handle = %q, want %q", got, want)
	}
	if recovery {
		t.Fatal("replica B recovery = true, want false")
	}
	// register/begin and register/finish both resolve the handoff. Reading from
	// replica B must not consume it before the second operation.
	gotAgain, _, _, err := replicaA.UserHandle(context.Background(), key)
	if err != nil {
		t.Fatalf("replica A second UserHandle: %v", err)
	}
	if string(gotAgain) != string(want) {
		t.Fatalf("replica A second handle = %q, want %q", gotAgain, want)
	}
}

// TestRedisEnrollmentSessionStore_RecoveryFlagRoundTrips proves the recovery
// flag survives the Redis-backed store's JSON envelope across replicas, the
// same handoff a recovered user's register/finish depends on to reach
// svc.FinishRecoveryRegistration.
func TestRedisEnrollmentSessionStore_RecoveryFlagRoundTrips(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // test cleanup
	store := NewRedisEnrollmentSessionStore(client)

	if err := store.Save(context.Background(), "recovering", []byte("user"), true, ""); err != nil {
		t.Fatalf("Save: %v", err)
	}
	handle, recovery, _, err := store.UserHandle(context.Background(), "recovering")
	if err != nil {
		t.Fatalf("UserHandle: %v", err)
	}
	if string(handle) != "user" {
		t.Fatalf("handle = %q, want %q", handle, "user")
	}
	if !recovery {
		t.Fatal("recovery = false, want true")
	}
}

// TestRedisEnrollmentSessionStore_ReturnToRoundTrips proves return_to
// survives the Redis-backed store's JSON envelope across replicas — the same
// carrier the post-registration handoff reads to copy return_to onto the
// issued BFF session (design.md Decision 5 / REQ-004).
func TestRedisEnrollmentSessionStore_ReturnToRoundTrips(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // test cleanup
	store := NewRedisEnrollmentSessionStore(client)

	if err := store.Save(context.Background(), "with-return-to", []byte("user"), false, "https://marketing.example/welcome"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	_, _, returnTo, err := store.UserHandle(context.Background(), "with-return-to")
	if err != nil {
		t.Fatalf("UserHandle: %v", err)
	}
	if returnTo != "https://marketing.example/welcome" {
		t.Fatalf("returnTo = %q, want %q", returnTo, "https://marketing.example/welcome")
	}
}

func TestRedisEnrollmentSessionStore_ExpiresFailClosed(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // test cleanup
	store := NewRedisEnrollmentSessionStore(client)

	if err := store.Save(context.Background(), "expired", []byte("user"), false, ""); err != nil {
		t.Fatalf("Save: %v", err)
	}
	mr.FastForward(enrollmentSessionTTL + time.Second)
	if _, _, _, err := store.UserHandle(context.Background(), "expired"); !errors.Is(err, ErrEnrollmentSessionNotFound) {
		t.Fatalf("UserHandle(expired) = %v, want ErrEnrollmentSessionNotFound", err)
	}
}
