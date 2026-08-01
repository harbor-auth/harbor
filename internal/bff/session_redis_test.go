package bff

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/harbor-auth/harbor/internal/oidc"
	"github.com/redis/go-redis/v9"
)

func newTestRedisStore(t *testing.T) (*RedisBFFSessionStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // t.Cleanup cannot propagate errors // test cleanup; error not actionable
	return NewRedisBFFSessionStore(client, 5*time.Minute), mr
}

func TestRedisBFFSessionStore_CreateAndGet(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()

	record := BFFSessionRecord{
		RequestID:   "req-123",
		State:       "state-abc",
		ClientID:    "client-xyz",
		RedirectURI: "https://example.com/callback",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	got, err := store.Get(ctx, "req-123")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.RequestID != record.RequestID {
		t.Errorf("RequestID = %q, want %q", got.RequestID, record.RequestID)
	}
	if got.State != record.State {
		t.Errorf("State = %q, want %q", got.State, record.State)
	}
	if got.ClientID != record.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, record.ClientID)
	}
	if got.RedirectURI != record.RedirectURI {
		t.Errorf("RedirectURI = %q, want %q", got.RedirectURI, record.RedirectURI)
	}
}

func TestRedisBFFSessionStore_CreateDuplicate(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()

	record := BFFSessionRecord{
		RequestID: "req-123",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("first Create failed: %v", err)
	}

	err := store.Create(ctx, record)
	if err == nil {
		t.Fatal("expected error on duplicate Create, got nil")
	}
}

func TestRedisBFFSessionStore_GetNotFound(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent")
	if !errors.Is(err, ErrBFFSessionNotFound) {
		t.Errorf("Get(nonexistent) = %v, want ErrBFFSessionNotFound", err)
	}
}

func TestRedisBFFSessionStore_GetExpiredByTTL(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()

	record := BFFSessionRecord{
		RequestID: "req-123",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Fast-forward miniredis past the TTL
	mr.FastForward(6 * time.Minute)

	_, err := store.Get(ctx, "req-123")
	if !errors.Is(err, ErrBFFSessionNotFound) {
		t.Errorf("Get(expired by TTL) = %v, want ErrBFFSessionNotFound", err)
	}
}

func TestRedisBFFSessionStore_SetUser(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()

	record := BFFSessionRecord{
		RequestID: "req-123",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := store.SetUser(ctx, "req-123", "user-456"); err != nil {
		t.Fatalf("SetUser failed: %v", err)
	}

	got, err := store.Get(ctx, "req-123")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.UserID != "user-456" {
		t.Errorf("UserID = %q, want %q", got.UserID, "user-456")
	}
}

func TestRedisBFFSessionStore_SetUserNotFound(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()

	err := store.SetUser(ctx, "nonexistent", "user-456")
	if !errors.Is(err, ErrBFFSessionNotFound) {
		t.Errorf("SetUser(nonexistent) = %v, want ErrBFFSessionNotFound", err)
	}
}

func TestRedisBFFSessionStore_Delete(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()

	record := BFFSessionRecord{
		RequestID: "req-123",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := store.Delete(ctx, "req-123"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err := store.Get(ctx, "req-123")
	if !errors.Is(err, ErrBFFSessionNotFound) {
		t.Errorf("Get after Delete = %v, want ErrBFFSessionNotFound", err)
	}
}

func TestRedisBFFSessionStore_DeleteNonexistent(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()

	// Delete on nonexistent should be a no-op, not an error.
	if err := store.Delete(ctx, "nonexistent"); err != nil {
		t.Errorf("Delete(nonexistent) = %v, want nil", err)
	}
}

func TestRedisBFFSessionStore_SetUserPreservesTTL(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()

	record := BFFSessionRecord{
		RequestID: "req-123",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Fast-forward 2 minutes
	mr.FastForward(2 * time.Minute)

	if err := store.SetUser(ctx, "req-123", "user-456"); err != nil {
		t.Fatalf("SetUser failed: %v", err)
	}

	// Fast-forward another 2 minutes (total 4 min, less than original 5 min TTL)
	mr.FastForward(2 * time.Minute)

	// Session should still exist (TTL preserved, not reset)
	got, err := store.Get(ctx, "req-123")
	if err != nil {
		t.Fatalf("Get failed after SetUser: %v", err)
	}
	if got.UserID != "user-456" {
		t.Errorf("UserID = %q, want %q", got.UserID, "user-456")
	}
}

func TestRedisBFFSessionStore_SetAuthMethod(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()

	record := BFFSessionRecord{
		RequestID: "req-123",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := store.SetAuthMethod(ctx, "req-123", oidc.AuthMethodWebAuthn); err != nil {
		t.Fatalf("SetAuthMethod failed: %v", err)
	}

	got, err := store.Get(ctx, "req-123")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.AuthMethod != oidc.AuthMethodWebAuthn {
		t.Errorf("AuthMethod = %q, want %q", got.AuthMethod, oidc.AuthMethodWebAuthn)
	}
}

func TestRedisBFFSessionStore_SetAuthMethod_NotFound(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()

	err := store.SetAuthMethod(ctx, "nonexistent", oidc.AuthMethodWebAuthn)
	if !errors.Is(err, ErrBFFSessionNotFound) {
		t.Errorf("SetAuthMethod(nonexistent) = %v, want ErrBFFSessionNotFound", err)
	}
}

func TestRedisBFFSessionStore_SetAuthMethod_PreservesTTL(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()

	record := BFFSessionRecord{
		RequestID: "req-123",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Fast-forward 2 minutes, then set auth method.
	mr.FastForward(2 * time.Minute)

	if err := store.SetAuthMethod(ctx, "req-123", oidc.AuthMethodTOTP); err != nil {
		t.Fatalf("SetAuthMethod failed: %v", err)
	}

	// Fast-forward another 2 minutes (total 4 min, still within original 5 min TTL).
	mr.FastForward(2 * time.Minute)

	got, err := store.Get(ctx, "req-123")
	if err != nil {
		t.Fatalf("Get failed after SetAuthMethod: %v", err)
	}
	if got.AuthMethod != oidc.AuthMethodTOTP {
		t.Errorf("AuthMethod = %q, want %q", got.AuthMethod, oidc.AuthMethodTOTP)
	}
}

func TestRedisBFFSessionStore_BrowserNonceHashRoundTrip(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()

	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}

	record := BFFSessionRecord{
		RequestID:        "req-nonce",
		ExpiresAt:        time.Now().Add(5 * time.Minute),
		BrowserNonceHash: nonce,
	}

	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	got, err := store.Get(ctx, "req-nonce")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if len(got.BrowserNonceHash) != len(nonce) {
		t.Fatalf("BrowserNonceHash length = %d, want %d", len(got.BrowserNonceHash), len(nonce))
	}
	for i, b := range nonce {
		if got.BrowserNonceHash[i] != b {
			t.Errorf("BrowserNonceHash[%d] = %#x, want %#x", i, got.BrowserNonceHash[i], b)
		}
	}
}

func TestRedisBFFSessionStore_ConcurrentAccess(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()

	const numGoroutines = 20
	const numOpsPerGoroutine = 10

	// Create initial sessions
	for i := 0; i < numGoroutines; i++ {
		record := BFFSessionRecord{
			RequestID: "req-" + string(rune('A'+i)),
			State:     "state",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}
		if err := store.Create(ctx, record); err != nil {
			t.Fatalf("Create failed: %v", err)
		}
	}

	// Run concurrent operations
	done := make(chan bool, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()
			reqID := "req-" + string(rune('A'+id))
			for j := 0; j < numOpsPerGoroutine; j++ {
				// Mix of Get and SetUser operations
				if j%2 == 0 {
					_, _ = store.Get(ctx, reqID) //nolint:errcheck // concurrent stress test; errors intentional
				} else {
					_ = store.SetUser(ctx, reqID, "user-"+string(rune('0'+j%10))) //nolint:errcheck // concurrent stress test; errors intentional
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify data integrity - sessions should still be retrievable
	for i := 0; i < numGoroutines; i++ {
		reqID := "req-" + string(rune('A'+i))
		_, err := store.Get(ctx, reqID)
		if err != nil {
			t.Errorf("Get(%s) after concurrent access failed: %v", reqID, err)
		}
	}
}

func TestRedisBFFSessionStore_MutationsDoNotCreateMissingSessions(t *testing.T) {
	mutations := redisSessionMutations()
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			store, mr := newTestRedisStore(t)
			const requestID = "missing-session"

			err := mutate(context.Background(), store, requestID)
			if !errors.Is(err, ErrBFFSessionNotFound) {
				t.Fatalf("mutation error = %v, want ErrBFFSessionNotFound", err)
			}
			if mr.Exists(sessionKey(requestID)) {
				t.Fatal("mutation recreated a missing session")
			}
		})
	}
}

func TestRedisBFFSessionStore_MutationsRejectRecordsWithoutPositiveTTL(t *testing.T) {
	mutations := redisSessionMutations()
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			store, mr := newTestRedisStore(t)
			ctx := context.Background()
			const requestID = "non-expiring-session"
			record := BFFSessionRecord{
				RequestID: requestID,
				ExpiresAt: time.Now().Add(5 * time.Minute),
			}
			if err := store.Create(ctx, record); err != nil {
				t.Fatalf("Create: %v", err)
			}
			key := sessionKey(requestID)
			before, err := mr.Get(key)
			if err != nil {
				t.Fatalf("read seeded record: %v", err)
			}
			mr.SetTTL(key, 0)
			if ttl := mr.TTL(key); ttl > 0 {
				t.Fatalf("test setup TTL = %v, want non-positive", ttl)
			}

			err = mutate(ctx, store, requestID)
			if !errors.Is(err, ErrBFFSessionNotFound) {
				t.Fatalf("mutation error = %v, want ErrBFFSessionNotFound", err)
			}
			after, getErr := mr.Get(key)
			if getErr != nil {
				t.Fatalf("read record after rejected mutation: %v", getErr)
			}
			if after != before {
				t.Fatal("mutation rewrote a session whose TTL was non-positive")
			}
		})
	}
}

func redisSessionMutations() map[string]func(context.Context, *RedisBFFSessionStore, string) error {
	return map[string]func(context.Context, *RedisBFFSessionStore, string) error{
		"set user": func(ctx context.Context, store *RedisBFFSessionStore, requestID string) error {
			return store.SetUser(ctx, requestID, "user-456")
		},
		"set user recovery status": func(ctx context.Context, store *RedisBFFSessionStore, requestID string) error {
			return store.SetUserWithRecoveryStatus(ctx, requestID, "user-456", true)
		},
		"set MFA verified": func(ctx context.Context, store *RedisBFFSessionStore, requestID string) error {
			return store.SetMFAVerified(ctx, requestID, time.Now())
		},
		"set auth method": func(ctx context.Context, store *RedisBFFSessionStore, requestID string) error {
			return store.SetAuthMethod(ctx, requestID, oidc.AuthMethodWebAuthn)
		},
		"set consent pending": func(ctx context.Context, store *RedisBFFSessionStore, requestID string) error {
			return store.SetConsentPending(ctx, requestID)
		},
	}
}
