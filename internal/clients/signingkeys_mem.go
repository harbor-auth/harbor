package clients

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// MemorySigningKeyStore is an in-memory SigningKeyStore for local development
// and unit tests (docs/DESIGN.md §7.3). It is NOT durable — all keys are lost
// on restart — so the rotation overlap window cannot survive a replica restart.
// Production deployments MUST use DBSigningKeyStore, which persists key metadata
// in the signing_keys table so the overlap window survives restarts.
//
// MemorySigningKeyStore is safe for concurrent use.
type MemorySigningKeyStore struct {
	mu   sync.RWMutex
	byID map[string]*SigningKey // keyed by SigningKey.ID
}

// Compile-time proof that MemorySigningKeyStore implements SigningKeyStore.
var _ SigningKeyStore = (*MemorySigningKeyStore)(nil)

// NewMemorySigningKeyStore returns an empty in-memory signing key store.
func NewMemorySigningKeyStore() *MemorySigningKeyStore {
	return &MemorySigningKeyStore{byID: make(map[string]*SigningKey)}
}

// Create implements SigningKeyStore. It inserts a new key in 'pending' state.
// Returns an error if the ID is empty or if a key with the same ID or kid
// already exists (mirroring the DB's primary-key and unique-kid constraints).
func (s *MemorySigningKeyStore) Create(_ context.Context, key NewSigningKey) (SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if key.ID == "" {
		return SigningKey{}, fmt.Errorf("signingkeys: create: empty ID")
	}
	if _, exists := s.byID[key.ID]; exists {
		return SigningKey{}, fmt.Errorf("signingkeys: create: duplicate ID %q", key.ID)
	}
	for _, k := range s.byID {
		if k.Kid == key.Kid {
			return SigningKey{}, fmt.Errorf("signingkeys: create: duplicate kid %q", key.Kid)
		}
	}

	stored := &SigningKey{
		ID:                key.ID,
		Kid:               key.Kid,
		State:             "pending",
		PublicKeyBytes:    key.PublicKeyBytes,
		PrivateKeyWrapped: key.PrivateKeyWrapped,
		Region:            key.Region,
		CreatedAt:         time.Now(),
	}
	s.byID[key.ID] = stored
	return *stored, nil
}

// GetByKid implements SigningKeyStore. Returns ErrSigningKeyNotFound if no key
// exists with that kid.
func (s *MemorySigningKeyStore) GetByKid(_ context.Context, kid string) (SigningKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.byID {
		if k.Kid == kid {
			return *k, nil
		}
	}
	return SigningKey{}, ErrSigningKeyNotFound
}

// GetActive implements SigningKeyStore. Returns the active signing key, or
// ErrSigningKeyNotFound if none is active.
func (s *MemorySigningKeyStore) GetActive(_ context.Context) (SigningKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.byID {
		if k.State == "active" {
			return *k, nil
		}
	}
	return SigningKey{}, ErrSigningKeyNotFound
}

// ListLive implements SigningKeyStore. It returns all pending and active keys
// (the set published in JWKS), sorted by CreatedAt then Kid for deterministic
// output. Retired keys are excluded.
func (s *MemorySigningKeyStore) ListLive(_ context.Context) ([]SigningKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []SigningKey
	for _, k := range s.byID {
		if k.State == "pending" || k.State == "active" {
			out = append(out, *k)
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

// SetState implements SigningKeyStore. It updates the key's state and replaces
// its promoted_at / retired_at timestamps with the supplied values (nil clears
// the timestamp), matching DBSigningKeyStore.SetState. Returns
// ErrSigningKeyNotFound if no key has the given ID.
func (s *MemorySigningKeyStore) SetState(_ context.Context, id string, state string, promotedAt, retiredAt *time.Time) (SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.byID[id]
	if !ok {
		return SigningKey{}, ErrSigningKeyNotFound
	}
	k.State = state
	k.PromotedAt = copyTimePtr(promotedAt)
	k.RetiredAt = copyTimePtr(retiredAt)
	return *k, nil
}

// Retire implements SigningKeyStore. It marks the key with the given kid as
// retired and stamps retired_at. Returns ErrSigningKeyNotFound if no key has
// that kid.
func (s *MemorySigningKeyStore) Retire(_ context.Context, kid string) (SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.byID {
		if k.Kid == kid {
			now := time.Now()
			k.State = "retired"
			k.RetiredAt = &now
			return *k, nil
		}
	}
	return SigningKey{}, ErrSigningKeyNotFound
}

// copyTimePtr returns a deep copy of a *time.Time so stored timestamps never
// alias a caller-owned pointer.
func copyTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}
