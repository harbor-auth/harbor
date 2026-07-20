package crypto

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeRotationStore is an in-memory RotationStore for KeyRotator tests.
type fakeRotationStore struct {
	mu   sync.Mutex
	keys map[string]*fakeKeyRow // by kid
}

type fakeKeyRow struct {
	state      KeyState
	region     string
	createdAt  time.Time
	promotedAt *time.Time
	retiredAt  *time.Time
}

func newFakeRotationStore() *fakeRotationStore {
	return &fakeRotationStore{keys: make(map[string]*fakeKeyRow)}
}

func (s *fakeRotationStore) Create(_ context.Context, key NewKeyMaterial) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.keys[key.Kid]; exists {
		return errors.New("duplicate kid")
	}
	s.keys[key.Kid] = &fakeKeyRow{
		state:     KeyStatePending,
		region:    key.Region,
		createdAt: key.CreatedAt,
	}
	return nil
}

func (s *fakeRotationStore) ActiveKid(_ context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for kid, row := range s.keys {
		if row.state == KeyStateActive {
			return kid, nil
		}
	}
	return "", nil
}

func (s *fakeRotationStore) Promote(_ context.Context, kid string, promotedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.keys[kid]
	if !ok {
		return errors.New("unknown kid")
	}
	row.state = KeyStateActive
	t := promotedAt
	row.promotedAt = &t
	return nil
}

func (s *fakeRotationStore) Retire(_ context.Context, kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.keys[kid]
	if !ok {
		return errors.New("unknown kid")
	}
	row.state = KeyStateRetired
	now := time.Now()
	row.retiredAt = &now
	return nil
}

func (s *fakeRotationStore) stateOf(kid string) KeyState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if row, ok := s.keys[kid]; ok {
		return row.state
	}
	return ""
}

// newTestRotator wires a KeyRotator with an initial active signer already
// present in both the provider and the store. It returns the rotator, the
// store, the provider, and the initial (old) kid.
func newTestRotator(t *testing.T, cfg RotationConfig) (*KeyRotator, *fakeRotationStore, *MultiKeyProvider, string) {
	t.Helper()
	initial := mustSigner(t)
	provider, err := NewMultiKeyProvider(initial)
	if err != nil {
		t.Fatalf("NewMultiKeyProvider: %v", err)
	}
	store := newFakeRotationStore()
	// Seed the store with the initial key already active.
	if err := store.Create(context.Background(), NewKeyMaterial{Kid: initial.KeyID(), CreatedAt: time.Now()}); err != nil {
		t.Fatalf("seed create: %v", err)
	}
	if err := store.Promote(context.Background(), initial.KeyID(), time.Now()); err != nil {
		t.Fatalf("seed promote: %v", err)
	}
	rotator := NewKeyRotator(NewRotationManager(cfg), provider, store)
	return rotator, store, provider, initial.KeyID()
}

func TestKeyRotatorScheduledRotation(t *testing.T) {
	rotator, store, provider, oldKid := newTestRotator(t, DefaultRotationConfig())
	ctx := context.Background()

	res, err := rotator.Rotate(ctx, RotateOptions{Region: "us"})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if res.NewKid == "" {
		t.Fatal("expected a new kid")
	}
	if res.OldKid != oldKid {
		t.Errorf("OldKid: got %q, want %q", res.OldKid, oldKid)
	}
	if res.Emergency {
		t.Error("scheduled rotation must not be flagged emergency")
	}

	// New key is pending (published in JWKS) but the old key is still active.
	if store.stateOf(res.NewKid) != KeyStatePending {
		t.Errorf("new key state: got %q, want pending", store.stateOf(res.NewKid))
	}
	if store.stateOf(oldKid) != KeyStateActive {
		t.Errorf("old key state before promote: got %q, want active", store.stateOf(oldKid))
	}
	// JWKS now contains BOTH kids.
	if got := len(provider.AllSigners()); got != 2 {
		t.Fatalf("JWKS signer count after rotate: got %d, want 2", got)
	}
	// The active signer is still the old one until promotion.
	if provider.ActiveSigner().KeyID() != oldKid {
		t.Errorf("active signer before promote: got %q, want old %q", provider.ActiveSigner().KeyID(), oldKid)
	}

	// Promote the new key.
	if err := rotator.Promote(ctx, res.NewKid); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if provider.ActiveSigner().KeyID() != res.NewKid {
		t.Errorf("active signer after promote: got %q, want new %q", provider.ActiveSigner().KeyID(), res.NewKid)
	}
	if store.stateOf(res.NewKid) != KeyStateActive {
		t.Errorf("new key state after promote: got %q, want active", store.stateOf(res.NewKid))
	}
	// Old key is draining: still live in JWKS during the overlap window.
	if _, ok := provider.SignerByKid(oldKid); !ok {
		t.Error("old key must remain in JWKS during overlap window")
	}

	// Retire the old key.
	if err := rotator.Retire(ctx, oldKid); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if store.stateOf(oldKid) != KeyStateRetired {
		t.Errorf("old key state after retire: got %q, want retired", store.stateOf(oldKid))
	}
	if _, ok := provider.SignerByKid(oldKid); ok {
		t.Error("retired key must be removed from JWKS")
	}
	if got := len(provider.AllSigners()); got != 1 {
		t.Fatalf("JWKS signer count after retire: got %d, want 1", got)
	}
}

func TestKeyRotatorEmergencyRotation(t *testing.T) {
	rotator, store, provider, oldKid := newTestRotator(t, DefaultRotationConfig())
	ctx := context.Background()

	res, err := rotator.Rotate(ctx, RotateOptions{Emergency: true})
	if err != nil {
		t.Fatalf("Rotate emergency: %v", err)
	}
	if !res.Emergency {
		t.Error("emergency rotation must be flagged emergency")
	}

	// New key is active immediately; old key is retired immediately.
	if store.stateOf(res.NewKid) != KeyStateActive {
		t.Errorf("new key state: got %q, want active", store.stateOf(res.NewKid))
	}
	if store.stateOf(oldKid) != KeyStateRetired {
		t.Errorf("old key state: got %q, want retired", store.stateOf(oldKid))
	}
	if provider.ActiveSigner().KeyID() != res.NewKid {
		t.Errorf("active signer: got %q, want new %q", provider.ActiveSigner().KeyID(), res.NewKid)
	}
	// Old key is gone from JWKS immediately (nuclear option).
	if _, ok := provider.SignerByKid(oldKid); ok {
		t.Error("emergency rotation must remove old key from JWKS immediately")
	}
	if got := len(provider.AllSigners()); got != 1 {
		t.Fatalf("JWKS signer count: got %d, want 1", got)
	}
}

func TestKeyRotatorFirstRotationNoActiveKey(t *testing.T) {
	// Provider seeded with a signer, but the store has NO active key — the
	// first-ever rotation must handle an empty oldKid.
	initial := mustSigner(t)
	provider, err := NewMultiKeyProvider(initial)
	if err != nil {
		t.Fatalf("NewMultiKeyProvider: %v", err)
	}
	store := newFakeRotationStore()
	rotator := NewKeyRotator(NewRotationManager(EmergencyRotationConfig()), provider, store)
	ctx := context.Background()

	res, err := rotator.Rotate(ctx, RotateOptions{Emergency: true})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if res.OldKid != "" {
		t.Errorf("OldKid: got %q, want empty", res.OldKid)
	}
	if res.RetireOldAt != (time.Time{}) {
		t.Errorf("RetireOldAt should be zero with no old key, got %v", res.RetireOldAt)
	}
	if store.stateOf(res.NewKid) != KeyStateActive {
		t.Errorf("new key state: got %q, want active", store.stateOf(res.NewKid))
	}
}

func TestKeyRotatorScheduleTimes(t *testing.T) {
	rotator, _, _, _ := newTestRotator(t, DefaultRotationConfig())
	fixed := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	rotator = rotator.WithClock(func() time.Time { return fixed })
	ctx := context.Background()

	res, err := rotator.Rotate(ctx, RotateOptions{})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	wantPromote := fixed.Add(DefaultRotationConfig().GracePeriod)
	if !res.PromoteAt.Equal(wantPromote) {
		t.Errorf("PromoteAt: got %v, want %v", res.PromoteAt, wantPromote)
	}
	wantRetire := wantPromote.Add(DefaultRotationConfig().OverlapWindow)
	if !res.RetireOldAt.Equal(wantRetire) {
		t.Errorf("RetireOldAt: got %v, want %v", res.RetireOldAt, wantRetire)
	}
}

func TestKeyRotatorGeneratorError(t *testing.T) {
	rotator, _, _, _ := newTestRotator(t, DefaultRotationConfig())
	wantErr := errors.New("hsm unavailable")
	rotator = rotator.WithGenerator(func() (Signer, error) { return nil, wantErr })

	_, err := rotator.Rotate(context.Background(), RotateOptions{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected generator error to propagate, got %v", err)
	}
}
