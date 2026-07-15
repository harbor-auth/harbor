package clients

import (
	"context"
	"errors"
	"testing"
	"time"
)

func newTestSigningKey(id, kid string) NewSigningKey {
	return NewSigningKey{
		ID:                id,
		Kid:               kid,
		PublicKeyBytes:    []byte("pub-" + kid),
		PrivateKeyWrapped: []byte("wrapped-" + kid),
		Region:            "us",
	}
}

func TestMemorySigningKeyStoreImplementsInterface(t *testing.T) {
	var _ SigningKeyStore = (*MemorySigningKeyStore)(nil)
}

func TestMemorySigningKeyStoreCreateAndGetByKid(t *testing.T) {
	s := NewMemorySigningKeyStore()
	ctx := context.Background()

	created, err := s.Create(ctx, newTestSigningKey("id-1", "kid-1"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.State != "pending" {
		t.Errorf("new key state: got %q, want pending", created.State)
	}
	if created.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set on create")
	}

	got, err := s.GetByKid(ctx, "kid-1")
	if err != nil {
		t.Fatalf("GetByKid: %v", err)
	}
	if got.ID != "id-1" || got.Kid != "kid-1" {
		t.Errorf("GetByKid mismatch: got id=%q kid=%q", got.ID, got.Kid)
	}
	if string(got.PublicKeyBytes) != "pub-kid-1" {
		t.Errorf("PublicKeyBytes mismatch: got %q", got.PublicKeyBytes)
	}
}

func TestMemorySigningKeyStoreCreateDuplicateID(t *testing.T) {
	s := NewMemorySigningKeyStore()
	ctx := context.Background()
	if _, err := s.Create(ctx, newTestSigningKey("id-1", "kid-1")); err != nil {
		t.Fatalf("Create 1: %v", err)
	}
	if _, err := s.Create(ctx, newTestSigningKey("id-1", "kid-2")); err == nil {
		t.Error("expected error for duplicate ID")
	}
}

func TestMemorySigningKeyStoreCreateDuplicateKid(t *testing.T) {
	s := NewMemorySigningKeyStore()
	ctx := context.Background()
	if _, err := s.Create(ctx, newTestSigningKey("id-1", "kid-1")); err != nil {
		t.Fatalf("Create 1: %v", err)
	}
	if _, err := s.Create(ctx, newTestSigningKey("id-2", "kid-1")); err == nil {
		t.Error("expected error for duplicate kid")
	}
}

func TestMemorySigningKeyStoreCreateEmptyID(t *testing.T) {
	s := NewMemorySigningKeyStore()
	if _, err := s.Create(context.Background(), newTestSigningKey("", "kid-1")); err == nil {
		t.Error("expected error for empty ID")
	}
}

func TestMemorySigningKeyStoreGetByKidNotFound(t *testing.T) {
	s := NewMemorySigningKeyStore()
	_, err := s.GetByKid(context.Background(), "missing")
	if !errors.Is(err, ErrSigningKeyNotFound) {
		t.Fatalf("expected ErrSigningKeyNotFound, got %v", err)
	}
}

func TestMemorySigningKeyStoreGetActive(t *testing.T) {
	s := NewMemorySigningKeyStore()
	ctx := context.Background()

	// No active key yet.
	if _, err := s.GetActive(ctx); !errors.Is(err, ErrSigningKeyNotFound) {
		t.Fatalf("expected ErrSigningKeyNotFound with no active key, got %v", err)
	}

	if _, err := s.Create(ctx, newTestSigningKey("id-1", "kid-1")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	now := time.Now()
	if _, err := s.SetState(ctx, "id-1", "active", &now, nil); err != nil {
		t.Fatalf("SetState: %v", err)
	}

	active, err := s.GetActive(ctx)
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if active.Kid != "kid-1" {
		t.Errorf("GetActive: got kid %q, want kid-1", active.Kid)
	}
	if active.PromotedAt == nil {
		t.Error("PromotedAt should be set for active key")
	}
}

func TestMemorySigningKeyStoreListLive(t *testing.T) {
	s := NewMemorySigningKeyStore()
	ctx := context.Background()

	if _, err := s.Create(ctx, newTestSigningKey("id-1", "kid-1")); err != nil {
		t.Fatalf("Create 1: %v", err)
	}
	if _, err := s.Create(ctx, newTestSigningKey("id-2", "kid-2")); err != nil {
		t.Fatalf("Create 2: %v", err)
	}
	now := time.Now()
	if _, err := s.SetState(ctx, "id-1", "active", &now, nil); err != nil {
		t.Fatalf("SetState active: %v", err)
	}

	// Both pending+active should be live.
	live, err := s.ListLive(ctx)
	if err != nil {
		t.Fatalf("ListLive: %v", err)
	}
	if len(live) != 2 {
		t.Fatalf("expected 2 live keys, got %d", len(live))
	}

	// Retire id-1 — it must drop out of the live set.
	if _, err := s.Retire(ctx, "kid-1"); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	live, err = s.ListLive(ctx)
	if err != nil {
		t.Fatalf("ListLive after retire: %v", err)
	}
	if len(live) != 1 {
		t.Fatalf("expected 1 live key after retire, got %d", len(live))
	}
	if live[0].Kid != "kid-2" {
		t.Errorf("remaining live key: got %q, want kid-2", live[0].Kid)
	}
}

func TestMemorySigningKeyStoreSetStateNotFound(t *testing.T) {
	s := NewMemorySigningKeyStore()
	_, err := s.SetState(context.Background(), "missing", "active", nil, nil)
	if !errors.Is(err, ErrSigningKeyNotFound) {
		t.Fatalf("expected ErrSigningKeyNotFound, got %v", err)
	}
}

func TestMemorySigningKeyStoreRetireNotFound(t *testing.T) {
	s := NewMemorySigningKeyStore()
	_, err := s.Retire(context.Background(), "missing")
	if !errors.Is(err, ErrSigningKeyNotFound) {
		t.Fatalf("expected ErrSigningKeyNotFound, got %v", err)
	}
}

// TestMemorySigningKeyStoreLifecycle exercises the full pending → active →
// retired lifecycle, mirroring how the rotation manager drives the store.
func TestMemorySigningKeyStoreLifecycle(t *testing.T) {
	s := NewMemorySigningKeyStore()
	ctx := context.Background()

	if _, err := s.Create(ctx, newTestSigningKey("id-1", "kid-1")); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Promote to active.
	promotedAt := time.Now()
	promoted, err := s.SetState(ctx, "id-1", "active", &promotedAt, nil)
	if err != nil {
		t.Fatalf("SetState active: %v", err)
	}
	if promoted.State != "active" || promoted.PromotedAt == nil {
		t.Fatalf("promote failed: state=%q promotedAt=%v", promoted.State, promoted.PromotedAt)
	}

	// Retire.
	retired, err := s.Retire(ctx, "kid-1")
	if err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if retired.State != "retired" || retired.RetiredAt == nil {
		t.Fatalf("retire failed: state=%q retiredAt=%v", retired.State, retired.RetiredAt)
	}

	// Retired key is gone from the live set and has no active key.
	if _, err := s.GetActive(ctx); !errors.Is(err, ErrSigningKeyNotFound) {
		t.Errorf("expected no active key after retire, got %v", err)
	}
	live, err := s.ListLive(ctx)
	if err != nil {
		t.Fatalf("ListLive: %v", err)
	}
	if len(live) != 0 {
		t.Errorf("expected no live keys after retire, got %d", len(live))
	}
}
