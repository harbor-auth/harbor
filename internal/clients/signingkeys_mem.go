package clients

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Signing key lifecycle states, mirroring the signing_keys table CHECK
// constraint (docs/DESIGN.md §7.3). Kept as local string literals so the
// clients package stays decoupled from internal/crypto.
const (
	signingKeyStatePending = "pending"
	signingKeyStateActive  = "active"
	signingKeyStateRetired = "retired"
)

// MemSigningKeyStore is an in-memory SigningKeyStore for unit tests and
// single-replica / local-dev use. It faithfully implements the SigningKeyStore
// contract (docs/DESIGN.md §7.3) without a database:
//
//   - Create inserts a new key in 'pending' state.
//   - GetActive returns the single active key (ErrSigningKeyNotFound if none).
//   - ListLive returns pending + active keys (retired excluded), in a stable
//     order (CreatedAt then Kid) for deterministic tests.
//   - SetState updates state and, using COALESCE semantics, only overwrites a
//     timestamp when the corresponding pointer is non-nil (so retiring a key
//     preserves its promoted_at, matching the DB store).
//   - Retire marks a key retired by kid and stamps retired_at.
//
// MemSigningKeyStore is safe for concurrent use.
type MemSigningKeyStore struct {
	mu    sync.Mutex
	keys  map[string]SigningKey // keyed by ID
	clock func() time.Time
}

// Compile-time proof that MemSigningKeyStore implements SigningKeyStore.
var _ SigningKeyStore = (*MemSigningKeyStore)(nil)

// NewMemSigningKeyStore returns an empty in-memory SigningKeyStore using the
// real wall clock.
func NewMemSigningKeyStore() *MemSigningKeyStore {
	return &MemSigningKeyStore{
		keys:  make(map[string]SigningKey),
		clock: time.Now,
	}
}

// WithClock sets a custom time source (for deterministic tests) and returns the
// store for chaining.
func (s *MemSigningKeyStore) WithClock(clock func() time.Time) *MemSigningKeyStore {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clock = clock
	return s
}

// Create implements SigningKeyStore. The new key enters 'pending' state with
// CreatedAt set from the store clock. Duplicate ID or kid is rejected.
func (s *MemSigningKeyStore) Create(_ context.Context, key NewSigningKey) (SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if key.ID == "" {
		return SigningKey{}, fmt.Errorf("signingkeys: create: empty ID")
	}
	if _, ok := s.keys[key.ID]; ok {
		return SigningKey{}, fmt.Errorf("signingkeys: create: duplicate ID %q", key.ID)
	}
	for _, k := range s.keys {
		if k.Kid == key.Kid {
			return SigningKey{}, fmt.Errorf("signingkeys: create: duplicate kid %q", key.Kid)
		}
	}

	sk := SigningKey{
		ID:                key.ID,
		Kid:               key.Kid,
		State:             signingKeyStatePending,
		PublicKeyBytes:    key.PublicKeyBytes,
		PrivateKeyWrapped: key.PrivateKeyWrapped,
		Region:            key.Region,
		CreatedAt:         s.clock(),
	}
	s.keys[sk.ID] = sk
	return sk, nil
}

// GetByKid implements SigningKeyStore.
func (s *MemSigningKeyStore) GetByKid(_ context.Context, kid string) (SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keys {
		if k.Kid == kid {
			return k, nil
		}
	}
	return SigningKey{}, ErrSigningKeyNotFound
}

// GetActive implements SigningKeyStore. Returns ErrSigningKeyNotFound when no
// key is in the active state.
func (s *MemSigningKeyStore) GetActive(_ context.Context) (SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keys {
		if k.State == signingKeyStateActive {
			return k, nil
		}
	}
	return SigningKey{}, ErrSigningKeyNotFound
}

// ListLive implements SigningKeyStore. Returns pending + active keys (retired
// excluded) sorted by CreatedAt then Kid for deterministic output.
func (s *MemSigningKeyStore) ListLive(_ context.Context) ([]SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []SigningKey
	for _, k := range s.keys {
		if k.State == signingKeyStatePending || k.State == signingKeyStateActive {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].Kid < out[j].Kid
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// SetState implements SigningKeyStore. It updates the key's state and, using
// COALESCE semantics, only overwrites promoted_at / retired_at when the
// corresponding argument is non-nil. Returns ErrSigningKeyNotFound if no key
// has the given id.
func (s *MemSigningKeyStore) SetState(_ context.Context, id string, state string, promotedAt, retiredAt *time.Time) (SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k, ok := s.keys[id]
	if !ok {
		return SigningKey{}, ErrSigningKeyNotFound
	}
	k.State = state
	if promotedAt != nil {
		t := *promotedAt
		k.PromotedAt = &t
	}
	if retiredAt != nil {
		t := *retiredAt
		k.RetiredAt = &t
	}
	s.keys[id] = k
	return k, nil
}

// Retire implements SigningKeyStore. It marks the key with the given kid as
// retired and stamps retired_at from the store clock. Returns
// ErrSigningKeyNotFound if no key has the given kid.
func (s *MemSigningKeyStore) Retire(_ context.Context, kid string) (SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, k := range s.keys {
		if k.Kid == kid {
			now := s.clock()
			k.State = signingKeyStateRetired
			k.RetiredAt = &now
			s.keys[id] = k
			return k, nil
		}
	}
	return SigningKey{}, ErrSigningKeyNotFound
}
