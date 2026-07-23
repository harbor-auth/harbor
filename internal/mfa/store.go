package mfa

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// StoredFactor is the FULL store-level view of a row in mfa_factors — including
// the sensitive envelope-encrypted TOTP secret and the bcrypt recovery-code
// hash. It never leaves the store↔service boundary: API and log surfaces get
// the metadata-only [Factor] (via Metadata) instead, so a secret can never be
// accidentally serialized (docs/DESIGN.md §6.5).
//
// Exactly one of Secret / CodeHash is populated per row: a TOTP factor carries
// Secret (CodeHash nil); a recovery-code factor carries CodeHash (Secret nil).
type StoredFactor struct {
	// ID is the factor's UUID (mfa_factors.id).
	ID string
	// UserID is the owning user's UUID (mfa_factors.user_id).
	UserID string
	// Region is the factor's home region; factors are region-pinned and never
	// cross-region replicated (mfa_factors.region, docs/DESIGN.md §10).
	Region string
	// Type is the factor kind (TOTP or recovery code).
	Type FactorType
	// Secret is the envelope-encrypted TOTP shared secret (mfa_factors.secret).
	// Nil for recovery-code factors.
	Secret []byte
	// CodeHash is the bcrypt hash of a recovery code (mfa_factors.code_hash).
	// Nil for TOTP factors.
	CodeHash []byte
	// Used reports whether a single-use factor (recovery code) has been burned.
	Used bool
	// CreatedAt is when the factor was enrolled (mfa_factors.created_at).
	CreatedAt time.Time
}

// Metadata projects a StoredFactor down to the metadata-only [Factor] that is
// safe to return from an API handler — the encrypted secret and recovery-code
// hash are dropped.
func (f StoredFactor) Metadata() Factor {
	return Factor{
		ID:        f.ID,
		UserID:    f.UserID,
		Region:    f.Region,
		Type:      f.Type,
		Used:      f.Used,
		CreatedAt: f.CreatedAt,
	}
}

// CreateFactorParams is the input for Store.CreateFactor. The store mints the
// factor's UUID itself and returns it on the resulting StoredFactor, so callers
// never supply an ID.
type CreateFactorParams struct {
	// UserID is the owning user's UUID.
	UserID string
	// Region is the user's home region (factors are region-pinned).
	Region string
	// Type is the factor kind (TOTP or recovery code).
	Type FactorType
	// Secret is the envelope-encrypted TOTP secret (set for TOTP factors, nil
	// for recovery codes). Encryption is the service's responsibility — the
	// store persists these bytes verbatim.
	Secret []byte
	// CodeHash is the bcrypt hash of a recovery code (set for recovery-code
	// factors, nil for TOTP factors).
	CodeHash []byte
}

// Store persists MFA factors (encrypted TOTP secrets and hashed recovery
// codes). In production it is backed by the sqlc queries over mfa_factors
// (db/queries/mfa_factors.sql); it is an interface so the TOTPService logic
// stays pure and unit-testable without a database (docs/DESIGN.md §1.7).
//
// The store deals only in already-encrypted secrets and already-hashed codes:
// it performs no crypto of its own. Encryption/hashing lives in the service.
type Store interface {
	// GetFactor returns a single factor by its ID, or ErrFactorNotFound.
	GetFactor(ctx context.Context, factorID string) (StoredFactor, error)
	// ListFactors returns all of a user's factors, newest first. An empty slice
	// (nil) means the user has no factors — it is NOT an error.
	ListFactors(ctx context.Context, userID string) ([]StoredFactor, error)
	// CreateFactor persists a new factor and returns it with its freshly-minted
	// ID and created-at timestamp populated.
	CreateFactor(ctx context.Context, params CreateFactorParams) (StoredFactor, error)
	// DeleteFactor removes a factor by ID. Deleting a missing factor is a no-op
	// (not an error), matching the underlying DELETE semantics.
	DeleteFactor(ctx context.Context, factorID string) error
	// MarkUsed burns a single-use factor (a recovery code) by flipping used
	// false → true. It only affects an unused factor, so a double-spend is a
	// harmless no-op; marking a missing factor is also a no-op.
	MarkUsed(ctx context.Context, factorID string) error
}

// InMemoryStore is a development/testing Store. It is NOT for production use —
// it holds encrypted secrets in process memory with no persistence. It exists
// so the TOTPService can be unit-tested without a database.
type InMemoryStore struct {
	mu      sync.RWMutex
	factors map[string]StoredFactor
	now     func() time.Time
}

// NewInMemoryStore returns an empty in-memory Store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		factors: make(map[string]StoredFactor),
		now:     time.Now,
	}
}

// GetFactor implements Store.
func (s *InMemoryStore) GetFactor(_ context.Context, factorID string) (StoredFactor, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.factors[factorID]
	if !ok {
		return StoredFactor{}, ErrFactorNotFound
	}
	return f, nil
}

// ListFactors implements Store: returns the user's factors sorted newest-first
// (matching the DB query's ORDER BY created_at DESC).
func (s *InMemoryStore) ListFactors(_ context.Context, userID string) ([]StoredFactor, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []StoredFactor
	for _, f := range s.factors {
		if f.UserID == userID {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// CreateFactor implements Store: mints a UUID + created-at and stores the
// factor.
func (s *InMemoryStore) CreateFactor(_ context.Context, params CreateFactorParams) (StoredFactor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := StoredFactor{
		ID:        uuid.NewString(),
		UserID:    params.UserID,
		Region:    params.Region,
		Type:      params.Type,
		Secret:    params.Secret,
		CodeHash:  params.CodeHash,
		Used:      false,
		CreatedAt: s.now(),
	}
	s.factors[f.ID] = f
	return f, nil
}

// DeleteFactor implements Store: removes the factor if present (no-op
// otherwise).
func (s *InMemoryStore) DeleteFactor(_ context.Context, factorID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.factors, factorID)
	return nil
}

// MarkUsed implements Store: flips used false → true for the factor. Marking an
// already-used or missing factor is a no-op, mirroring the DB query's
// `WHERE id = $1 AND used = false`.
func (s *InMemoryStore) MarkUsed(_ context.Context, factorID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.factors[factorID]
	if !ok {
		return nil
	}
	if !f.Used {
		f.Used = true
		s.factors[factorID] = f
	}
	return nil
}

// Compile-time assertion: InMemoryStore implements Store.
var _ Store = (*InMemoryStore)(nil)
