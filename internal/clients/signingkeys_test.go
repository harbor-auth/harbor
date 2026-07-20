package clients

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fixedClock returns a clock function that always yields t.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// newTestKey is a small helper for building NewSigningKey inputs.
func newTestKey(id, kid string) NewSigningKey {
	return NewSigningKey{
		ID:                id,
		Kid:               kid,
		PublicKeyBytes:    []byte("pub-" + kid),
		PrivateKeyWrapped: []byte("wrapped-" + kid),
		Region:            "eu-1",
	}
}

func TestMemSigningKeyStoreImplementsInterface(t *testing.T) {
	var _ SigningKeyStore = (*MemSigningKeyStore)(nil)
}

func TestMemSigningKeyStoreCreateAndGetByKid(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s := NewMemSigningKeyStore().WithClock(fixedClock(now))

	created, err := s.Create(ctx, newTestKey("11111111-1111-1111-1111-111111111111", "kid-a"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.State != signingKeyStatePending {
		t.Errorf("State: got %q, want pending", created.State)
	}
	if !created.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt: got %v, want %v", created.CreatedAt, now)
	}
	if created.PromotedAt != nil || created.RetiredAt != nil {
		t.Errorf("new key should have nil PromotedAt/RetiredAt")
	}
	if string(created.PublicKeyBytes) != "pub-kid-a" {
		t.Errorf("PublicKeyBytes not preserved: got %q", created.PublicKeyBytes)
	}
	if string(created.PrivateKeyWrapped) != "wrapped-kid-a" {
		t.Errorf("PrivateKeyWrapped not preserved: got %q", created.PrivateKeyWrapped)
	}
	if created.Region != "eu-1" {
		t.Errorf("Region: got %q, want eu-1", created.Region)
	}

	got, err := s.GetByKid(ctx, "kid-a")
	if err != nil {
		t.Fatalf("GetByKid: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("GetByKid ID: got %q, want %q", got.ID, created.ID)
	}
}

func TestMemSigningKeyStoreCreateDuplicateKid(t *testing.T) {
	ctx := context.Background()
	s := NewMemSigningKeyStore()
	if _, err := s.Create(ctx, newTestKey("id-1", "dup")); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if _, err := s.Create(ctx, newTestKey("id-2", "dup")); err == nil {
		t.Error("expected error creating key with duplicate kid")
	}
}

func TestMemSigningKeyStoreCreateDuplicateID(t *testing.T) {
	ctx := context.Background()
	s := NewMemSigningKeyStore()
	if _, err := s.Create(ctx, newTestKey("id-1", "kid-a")); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if _, err := s.Create(ctx, newTestKey("id-1", "kid-b")); err == nil {
		t.Error("expected error creating key with duplicate ID")
	}
}

func TestMemSigningKeyStoreCreateEmptyID(t *testing.T) {
	if _, err := NewMemSigningKeyStore().Create(context.Background(), newTestKey("", "kid")); err == nil {
		t.Error("expected error creating key with empty ID")
	}
}

func TestMemSigningKeyStoreGetByKidNotFound(t *testing.T) {
	_, err := NewMemSigningKeyStore().GetByKid(context.Background(), "missing")
	if !errors.Is(err, ErrSigningKeyNotFound) {
		t.Errorf("expected ErrSigningKeyNotFound, got %v", err)
	}
}

func TestMemSigningKeyStoreGetActiveNone(t *testing.T) {
	ctx := context.Background()
	s := NewMemSigningKeyStore()
	// A pending-only store has no active key.
	if _, err := s.Create(ctx, newTestKey("id-1", "kid-a")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err := s.GetActive(ctx)
	if !errors.Is(err, ErrSigningKeyNotFound) {
		t.Errorf("expected ErrSigningKeyNotFound, got %v", err)
	}
}

func TestMemSigningKeyStoreGetActive(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC)
	s := NewMemSigningKeyStore().WithClock(fixedClock(now))

	created, err := s.Create(ctx, newTestKey("id-1", "kid-a"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	promotedAt := now.Add(time.Minute)
	if _, err := s.SetState(ctx, created.ID, signingKeyStateActive, &promotedAt, nil); err != nil {
		t.Fatalf("SetState: %v", err)
	}

	active, err := s.GetActive(ctx)
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if active.Kid != "kid-a" {
		t.Errorf("GetActive Kid: got %q, want kid-a", active.Kid)
	}
	if active.PromotedAt == nil || !active.PromotedAt.Equal(promotedAt) {
		t.Errorf("PromotedAt: got %v, want %v", active.PromotedAt, promotedAt)
	}
}

func TestMemSigningKeyStoreListLive(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewMemSigningKeyStore()

	// Three keys created at increasing times for deterministic ordering.
	s.WithClock(fixedClock(base))
	k1, err := s.Create(ctx, newTestKey("id-1", "kid-1"))
	if err != nil {
		t.Fatalf("Create k1: %v", err)
	}
	s.WithClock(fixedClock(base.Add(1 * time.Hour)))
	k2, err := s.Create(ctx, newTestKey("id-2", "kid-2"))
	if err != nil {
		t.Fatalf("Create k2: %v", err)
	}
	s.WithClock(fixedClock(base.Add(2 * time.Hour)))
	k3, err := s.Create(ctx, newTestKey("id-3", "kid-3"))
	if err != nil {
		t.Fatalf("Create k3: %v", err)
	}

	// Promote k2 to active, retire k3. k1 stays pending.
	promoted := base.Add(90 * time.Minute)
	if _, err := s.SetState(ctx, k2.ID, signingKeyStateActive, &promoted, nil); err != nil {
		t.Fatalf("SetState active: %v", err)
	}
	if _, err := s.Retire(ctx, k3.Kid); err != nil {
		t.Fatalf("Retire: %v", err)
	}

	live, err := s.ListLive(ctx)
	if err != nil {
		t.Fatalf("ListLive: %v", err)
	}
	if len(live) != 2 {
		t.Fatalf("ListLive len: got %d, want 2 (retired excluded)", len(live))
	}
	// Sorted by CreatedAt: k1 (pending) then k2 (active).
	if live[0].Kid != k1.Kid || live[1].Kid != k2.Kid {
		t.Errorf("ListLive order: got [%s, %s], want [%s, %s]", live[0].Kid, live[1].Kid, k1.Kid, k2.Kid)
	}
}

func TestMemSigningKeyStoreSetStateNotFound(t *testing.T) {
	_, err := NewMemSigningKeyStore().SetState(context.Background(), "missing", signingKeyStateActive, nil, nil)
	if !errors.Is(err, ErrSigningKeyNotFound) {
		t.Errorf("expected ErrSigningKeyNotFound, got %v", err)
	}
}

// TestMemSigningKeyStoreSetStatePreservesTimestamps verifies COALESCE
// semantics: retiring via SetState (passing only retiredAt) must not clobber
// the previously-set promoted_at.
func TestMemSigningKeyStoreSetStatePreservesTimestamps(t *testing.T) {
	ctx := context.Background()
	s := NewMemSigningKeyStore()
	created, _ := s.Create(ctx, newTestKey("id-1", "kid-a"))

	promoted := time.Date(2026, 3, 3, 3, 0, 0, 0, time.UTC)
	if _, err := s.SetState(ctx, created.ID, signingKeyStateActive, &promoted, nil); err != nil {
		t.Fatalf("SetState active: %v", err)
	}

	retired := promoted.Add(15 * time.Minute)
	got, err := s.SetState(ctx, created.ID, signingKeyStateRetired, nil, &retired)
	if err != nil {
		t.Fatalf("SetState retired: %v", err)
	}
	if got.PromotedAt == nil || !got.PromotedAt.Equal(promoted) {
		t.Errorf("PromotedAt not preserved: got %v, want %v", got.PromotedAt, promoted)
	}
	if got.RetiredAt == nil || !got.RetiredAt.Equal(retired) {
		t.Errorf("RetiredAt: got %v, want %v", got.RetiredAt, retired)
	}
}

func TestMemSigningKeyStoreRetire(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 7, 7, 0, 0, 0, time.UTC)
	s := NewMemSigningKeyStore().WithClock(fixedClock(now))
	created, _ := s.Create(ctx, newTestKey("id-1", "kid-a"))

	got, err := s.Retire(ctx, created.Kid)
	if err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if got.State != signingKeyStateRetired {
		t.Errorf("State: got %q, want retired", got.State)
	}
	if got.RetiredAt == nil || !got.RetiredAt.Equal(now) {
		t.Errorf("RetiredAt: got %v, want %v", got.RetiredAt, now)
	}

	// A retired key is no longer live.
	live, err := s.ListLive(ctx)
	if err != nil {
		t.Fatalf("ListLive: %v", err)
	}
	if len(live) != 0 {
		t.Errorf("ListLive after retire: got %d, want 0", len(live))
	}
}

func TestMemSigningKeyStoreRetireNotFound(t *testing.T) {
	_, err := NewMemSigningKeyStore().Retire(context.Background(), "missing")
	if !errors.Is(err, ErrSigningKeyNotFound) {
		t.Errorf("expected ErrSigningKeyNotFound, got %v", err)
	}
}

// TestMemSigningKeyStoreLifecycle walks a key through the full
// pending → active → retired lifecycle, asserting GetActive and ListLive at
// each step.
func TestMemSigningKeyStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewMemSigningKeyStore().WithClock(fixedClock(base))

	key, err := s.Create(ctx, newTestKey("id-1", "kid-a"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Pending: live but not active.
	if _, err := s.GetActive(ctx); !errors.Is(err, ErrSigningKeyNotFound) {
		t.Errorf("pending: expected no active key, got %v", err)
	}
	if live, err := s.ListLive(ctx); err != nil || len(live) != 1 {
		t.Errorf("pending: ListLive got %d (err %v), want 1", len(live), err)
	}

	// Promote to active.
	promoted := base.Add(time.Minute)
	if _, err := s.SetState(ctx, key.ID, signingKeyStateActive, &promoted, nil); err != nil {
		t.Fatalf("promote: %v", err)
	}
	active, err := s.GetActive(ctx)
	if err != nil {
		t.Fatalf("GetActive after promote: %v", err)
	}
	if active.ID != key.ID {
		t.Errorf("active ID: got %q, want %q", active.ID, key.ID)
	}

	// Retire.
	if _, err := s.Retire(ctx, key.Kid); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if _, err := s.GetActive(ctx); !errors.Is(err, ErrSigningKeyNotFound) {
		t.Errorf("retired: expected no active key, got %v", err)
	}
	if live, err := s.ListLive(ctx); err != nil || len(live) != 0 {
		t.Errorf("retired: ListLive got %d (err %v), want 0", len(live), err)
	}
	// GetByKid still finds the retired key (it exists, just not live).
	if _, err := s.GetByKid(ctx, key.Kid); err != nil {
		t.Errorf("GetByKid on retired key: %v", err)
	}
}

// TestMemSigningKeyStoreConcurrent exercises the store from multiple goroutines
// to catch data races under `go test -race`.
func TestMemSigningKeyStoreConcurrent(t *testing.T) {
	ctx := context.Background()
	s := NewMemSigningKeyStore()

	const n = 25
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			id := "id-" + string(rune('a'+i))
			kid := "kid-" + string(rune('a'+i))
			if _, err := s.Create(ctx, newTestKey(id, kid)); err != nil {
				t.Errorf("Create: %v", err)
				return
			}
			// Concurrent readers; errors are expected/benign here (e.g. no
			// active key yet) — we only care that these don't race or panic.
			if _, err := s.GetByKid(ctx, kid); err != nil {
				t.Errorf("GetByKid(%s): %v", kid, err)
			}
			if _, err := s.ListLive(ctx); err != nil {
				t.Errorf("ListLive: %v", err)
			}
			if _, err := s.GetActive(ctx); err != nil && !errors.Is(err, ErrSigningKeyNotFound) {
				t.Errorf("GetActive: unexpected err %v", err)
			}
		}(i)
	}
	wg.Wait()

	live, err := s.ListLive(ctx)
	if err != nil {
		t.Fatalf("ListLive: %v", err)
	}
	if len(live) != n {
		t.Errorf("ListLive len: got %d, want %d", len(live), n)
	}
}
