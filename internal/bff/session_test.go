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
