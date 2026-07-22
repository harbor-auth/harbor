package bff

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestInMemoryBFFSessionStore_CreateAndGet(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
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

func TestInMemoryBFFSessionStore_CreateDuplicate(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
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

func TestInMemoryBFFSessionStore_GetNotFound(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent")
	if !errors.Is(err, ErrBFFSessionNotFound) {
		t.Errorf("Get(nonexistent) = %v, want ErrBFFSessionNotFound", err)
	}
}

func TestInMemoryBFFSessionStore_GetExpired(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	// Set a fixed "now" in the past so the session is already expired.
	pastTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return pastTime }

	record := BFFSessionRecord{
		RequestID: "req-123",
		ExpiresAt: pastTime.Add(-1 * time.Minute), // already expired
	}

	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	_, err := store.Get(ctx, "req-123")
	if !errors.Is(err, ErrBFFSessionExpired) {
		t.Errorf("Get(expired) = %v, want ErrBFFSessionExpired", err)
	}

	// Session should be deleted after expiry check.
	_, err = store.Get(ctx, "req-123")
	if !errors.Is(err, ErrBFFSessionNotFound) {
		t.Errorf("Get after expiry deletion = %v, want ErrBFFSessionNotFound", err)
	}
}

func TestInMemoryBFFSessionStore_SetUser(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
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

func TestInMemoryBFFSessionStore_SetUserNotFound(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	err := store.SetUser(ctx, "nonexistent", "user-456")
	if !errors.Is(err, ErrBFFSessionNotFound) {
		t.Errorf("SetUser(nonexistent) = %v, want ErrBFFSessionNotFound", err)
	}
}

func TestInMemoryBFFSessionStore_SetUserExpired(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	pastTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return pastTime }

	record := BFFSessionRecord{
		RequestID: "req-123",
		ExpiresAt: pastTime.Add(-1 * time.Minute),
	}

	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err := store.SetUser(ctx, "req-123", "user-456")
	if !errors.Is(err, ErrBFFSessionExpired) {
		t.Errorf("SetUser(expired) = %v, want ErrBFFSessionExpired", err)
	}
}

func TestInMemoryBFFSessionStore_Delete(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
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

func TestInMemoryBFFSessionStore_DeleteNonexistent(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	// Delete on nonexistent should be a no-op, not an error.
	if err := store.Delete(ctx, "nonexistent"); err != nil {
		t.Errorf("Delete(nonexistent) = %v, want nil", err)
	}
}

func TestInMemoryBFFSessionStore_SetUserWithRecoveryStatus(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	record := BFFSessionRecord{
		RequestID: "req-123",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Test with recovery required = true
	if err := store.SetUserWithRecoveryStatus(ctx, "req-123", "user-456", true); err != nil {
		t.Fatalf("SetUserWithRecoveryStatus failed: %v", err)
	}

	got, err := store.Get(ctx, "req-123")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.UserID != "user-456" {
		t.Errorf("UserID = %q, want %q", got.UserID, "user-456")
	}
	if !got.RecoveryRequired {
		t.Error("RecoveryRequired = false, want true")
	}
	if got.SessionScope != SessionScopeEnrollmentOnly {
		t.Errorf("SessionScope = %q, want %q", got.SessionScope, SessionScopeEnrollmentOnly)
	}
}

func TestInMemoryBFFSessionStore_SetUserWithRecoveryStatus_NoRecovery(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	record := BFFSessionRecord{
		RequestID: "req-456",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := store.Create(ctx, record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Test with recovery required = false
	if err := store.SetUserWithRecoveryStatus(ctx, "req-456", "user-789", false); err != nil {
		t.Fatalf("SetUserWithRecoveryStatus failed: %v", err)
	}

	got, err := store.Get(ctx, "req-456")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.UserID != "user-789" {
		t.Errorf("UserID = %q, want %q", got.UserID, "user-789")
	}
	if got.RecoveryRequired {
		t.Error("RecoveryRequired = true, want false")
	}
	if got.SessionScope != SessionScopeFull {
		t.Errorf("SessionScope = %q, want %q", got.SessionScope, SessionScopeFull)
	}
}

func TestInMemoryBFFSessionStore_SetUserWithRecoveryStatus_NotFound(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	err := store.SetUserWithRecoveryStatus(ctx, "nonexistent", "user-456", true)
	if !errors.Is(err, ErrBFFSessionNotFound) {
		t.Errorf("SetUserWithRecoveryStatus(nonexistent) = %v, want ErrBFFSessionNotFound", err)
	}
}

func TestInMemoryBFFSessionStore_ConcurrentAccess(t *testing.T) {
	store := NewInMemoryBFFSessionStore()
	ctx := context.Background()

	const numGoroutines = 50
	const numOpsPerGoroutine = 20

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
					_, _ = store.Get(ctx, reqID) //nolint:errcheck // goroutine cannot call t.Error
				} else {
					_ = store.SetUser(ctx, reqID, "user-"+string(rune('0'+j%10))) //nolint:errcheck // goroutine cannot call t.Error
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
