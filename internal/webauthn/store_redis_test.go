package webauthn

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
)

func newTestRedisSessionStore(t *testing.T) (*RedisSessionStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() }) //nolint:errcheck // test cleanup; error not actionable
	return NewRedisSessionStore(client, 5*time.Minute), mr
}

func TestRedisSessionStore_SaveAndTakeRoundTrip(t *testing.T) {
	store, _ := newTestRedisSessionStore(t)
	ctx := context.Background()

	// Create a SessionData with all relevant fields populated
	data := gowebauthn.SessionData{
		Challenge:            "test-challenge-base64",
		UserID:               []byte("user-123"),
		AllowedCredentialIDs: [][]byte{[]byte("cred-1"), []byte("cred-2")},
		UserVerification:     "required",
		// Note: Extensions and RelyingPartyID are also exported fields
	}

	if err := store.Save(ctx, "session-key-1", data); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	got, err := store.Take(ctx, "session-key-1")
	if err != nil {
		t.Fatalf("Take failed: %v", err)
	}

	// Verify all fields are preserved
	if got.Challenge != data.Challenge {
		t.Errorf("Challenge = %q, want %q", got.Challenge, data.Challenge)
	}
	if string(got.UserID) != string(data.UserID) {
		t.Errorf("UserID = %q, want %q", got.UserID, data.UserID)
	}
	if len(got.AllowedCredentialIDs) != len(data.AllowedCredentialIDs) {
		t.Errorf("AllowedCredentialIDs length = %d, want %d", len(got.AllowedCredentialIDs), len(data.AllowedCredentialIDs))
	}
	for i, cred := range got.AllowedCredentialIDs {
		if string(cred) != string(data.AllowedCredentialIDs[i]) {
			t.Errorf("AllowedCredentialIDs[%d] = %q, want %q", i, cred, data.AllowedCredentialIDs[i])
		}
	}
	if got.UserVerification != data.UserVerification {
		t.Errorf("UserVerification = %q, want %q", got.UserVerification, data.UserVerification)
	}
}

func TestRedisSessionStore_DoubleTakeReturnsErrSessionNotFound(t *testing.T) {
	store, _ := newTestRedisSessionStore(t)
	ctx := context.Background()

	data := gowebauthn.SessionData{Challenge: "one-time-challenge"}
	if err := store.Save(ctx, "session-key", data); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// First Take should succeed
	_, err := store.Take(ctx, "session-key")
	if err != nil {
		t.Fatalf("first Take failed: %v", err)
	}

	// Second Take must fail — sessions are single-use (replay defense)
	_, err = store.Take(ctx, "session-key")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("second Take = %v, want ErrSessionNotFound", err)
	}
}

func TestRedisSessionStore_ExpiredSessionReturnsErrSessionNotFound(t *testing.T) {
	store, mr := newTestRedisSessionStore(t)
	ctx := context.Background()

	data := gowebauthn.SessionData{Challenge: "expiring-challenge"}
	if err := store.Save(ctx, "session-key", data); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Fast-forward miniredis past the TTL (5 min + buffer)
	mr.FastForward(6 * time.Minute)

	_, err := store.Take(ctx, "session-key")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Take(expired) = %v, want ErrSessionNotFound", err)
	}
}

func TestRedisSessionStore_SaveDuplicateKeyReturnsErrSessionExists(t *testing.T) {
	store, _ := newTestRedisSessionStore(t)
	ctx := context.Background()

	data := gowebauthn.SessionData{Challenge: "original-challenge"}
	if err := store.Save(ctx, "session-key", data); err != nil {
		t.Fatalf("first Save failed: %v", err)
	}

	// Second Save with same key must fail (NX guard)
	data2 := gowebauthn.SessionData{Challenge: "duplicate-challenge"}
	err := store.Save(ctx, "session-key", data2)
	if !errors.Is(err, ErrSessionExists) {
		t.Errorf("duplicate Save = %v, want ErrSessionExists", err)
	}

	// Original data should still be retrievable
	got, err := store.Take(ctx, "session-key")
	if err != nil {
		t.Fatalf("Take after duplicate Save attempt failed: %v", err)
	}
	if got.Challenge != "original-challenge" {
		t.Errorf("Challenge = %q, want %q (original should be preserved)", got.Challenge, "original-challenge")
	}
}

func TestRedisSessionStore_TakeNonexistentReturnsErrSessionNotFound(t *testing.T) {
	store, _ := newTestRedisSessionStore(t)
	ctx := context.Background()

	_, err := store.Take(ctx, "nonexistent-key")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Take(nonexistent) = %v, want ErrSessionNotFound", err)
	}
}

func TestRedisSessionStore_ConcurrentTakeOnlyOneSucceeds(t *testing.T) {
	store, _ := newTestRedisSessionStore(t)
	ctx := context.Background()

	data := gowebauthn.SessionData{Challenge: "concurrent-challenge"}
	if err := store.Save(ctx, "session-key", data); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	const numGoroutines = 10
	var successCount atomic.Int32
	errCh := make(chan error, numGoroutines)
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Launch multiple goroutines trying to Take the same session
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_, err := store.Take(ctx, "session-key")
			if err == nil {
				successCount.Add(1)
			} else if !errors.Is(err, ErrSessionNotFound) {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	// Check for unexpected errors
	for err := range errCh {
		t.Errorf("unexpected error: %v", err)
	}

	// Exactly one goroutine should succeed (Lua atomicity guarantee)
	if got := successCount.Load(); got != 1 {
		t.Errorf("successful Takes = %d, want exactly 1", got)
	}
}

func TestRedisSessionStore_KeyPrefix(t *testing.T) {
	store, mr := newTestRedisSessionStore(t)
	ctx := context.Background()

	data := gowebauthn.SessionData{Challenge: "test"}
	if err := store.Save(ctx, "my-key", data); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify the key has the expected prefix in Redis
	keys := mr.Keys()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0] != "webauthn_session:my-key" {
		t.Errorf("key = %q, want %q", keys[0], "webauthn_session:my-key")
	}
}

func TestRedisSessionStore_ChallengeBytesFidelity(t *testing.T) {
	store, _ := newTestRedisSessionStore(t)
	ctx := context.Background()

	// 32-byte challenge (typical WebAuthn challenge size)
	challenge := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
	data := gowebauthn.SessionData{
		Challenge: challenge,
		UserID:    []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}, // binary bytes
	}

	if err := store.Save(ctx, "binary-test", data); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	got, err := store.Take(ctx, "binary-test")
	if err != nil {
		t.Fatalf("Take failed: %v", err)
	}

	if got.Challenge != challenge {
		t.Errorf("Challenge mismatch")
	}
	if len(got.UserID) != len(data.UserID) {
		t.Errorf("UserID length = %d, want %d", len(got.UserID), len(data.UserID))
	}
	for i := range got.UserID {
		if got.UserID[i] != data.UserID[i] {
			t.Errorf("UserID[%d] = %d, want %d", i, got.UserID[i], data.UserID[i])
		}
	}
}
