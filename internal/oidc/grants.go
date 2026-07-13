package oidc

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Grant is the domain representation of a user<->RP consent record
// (docs/DESIGN.md §10, §11.3). It carries only stdlib types so internal/oidc
// remains free of DB-layer dependencies (internal/clients does the mapping).
type Grant struct {
	ID          string    // UUID string
	Region      string    // user's home jurisdiction (DESIGN §5.4)
	UserID      string    // UUID string
	ClientID    string    // relying_parties.client_id
	PairwiseSub string    // PPID this RP sees for this user (DESIGN §3.2)
	Scopes      []string  // consented scopes
	CreatedAt   time.Time
	RevokedAt   *time.Time // nil = active grant
}

// NewGrant is the input to GrantStore.CreateGrant. The store is responsible for
// minting the ID and setting CreatedAt; the caller supplies the region so the
// row satisfies the user-owned-row contract (DESIGN §10).
type NewGrant struct {
	Region      string
	UserID      string
	ClientID    string
	PairwiseSub string
	Scopes      []string
}

// GrantStore persists and queries consent grants (user<->RP relationships).
// The sqlc-backed implementation is in internal/clients; an in-memory stub is
// available for unit tests that do not require a live DB.
//
// FindGrant mirrors the (T, bool, error) convention of ClientRegistry.Lookup:
// found=false means no active grant exists (not an error).
type GrantStore interface {
	// FindGrant looks up the active (non-revoked) grant for a (userID, clientID)
	// pair. found=false means the user has not (yet) consented.
	FindGrant(ctx context.Context, userID, clientID string) (Grant, bool, error)

	// CreateGrant records a new consent. The store mints the grant ID.
	CreateGrant(ctx context.Context, g NewGrant) (Grant, error)

	// RevokeGrant soft-deletes a grant by its UUID string ID.
	RevokeGrant(ctx context.Context, id string) error

	// ListGrantsByUser returns all active (non-revoked) grants for a user,
	// newest first — powers the "connected apps" dashboard (DESIGN §11.3).
	ListGrantsByUser(ctx context.Context, userID string) ([]Grant, error)
}

// noopGrantStore is a GrantStore that records nothing. Used as the default in
// ServiceConfig when no persistent store is wired (e.g. dev/test scaffolds that
// auto-approve consent without persisting it).
type noopGrantStore struct{}

func (noopGrantStore) FindGrant(_ context.Context, _, _ string) (Grant, bool, error) {
	return Grant{}, false, nil
}
func (noopGrantStore) CreateGrant(_ context.Context, _ NewGrant) (Grant, error) {
	return Grant{}, nil
}
func (noopGrantStore) RevokeGrant(_ context.Context, _ string) error { return nil }
func (noopGrantStore) ListGrantsByUser(_ context.Context, _ string) ([]Grant, error) {
	return nil, nil
}

// InMemoryGrantStore is a dev/test GrantStore. NOT for production — a real store
// persists grants durably so they survive restarts (internal/clients.DBGrantStore).
type InMemoryGrantStore struct {
	mu      sync.Mutex
	byID    map[string]*Grant
	byPair  map[string]*Grant // key: userID+":"+clientID
	counter int               // monotonically increasing; never decrements so IDs stay unique even if grants were deleted
}

// NewInMemoryGrantStore returns an empty in-memory grant store.
func NewInMemoryGrantStore() *InMemoryGrantStore {
	return &InMemoryGrantStore{
		byID:   make(map[string]*Grant),
		byPair: make(map[string]*Grant),
	}
}

// FindGrant implements GrantStore. Returns only active (non-revoked) grants.
func (s *InMemoryGrantStore) FindGrant(_ context.Context, userID, clientID string) (Grant, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byPair[userID+":"+clientID]
	if !ok || g.RevokedAt != nil {
		return Grant{}, false, nil
	}
	return *g, true, nil
}

// CreateGrant implements GrantStore. Mints a sequential string ID.
// If an active grant already exists for the (userID, clientID) pair, it is
// soft-deleted before the new one is created — mirroring the DB UNIQUE index
// semantics on (user_id, client_id) for active grants. Without this, the old
// pointer in byID would become orphaned (FindGrant via byPair would shadow it,
// but ListGrantsByUser via byID would not, producing inconsistent results).
func (s *InMemoryGrantStore) CreateGrant(_ context.Context, ng NewGrant) (Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Soft-delete any existing ACTIVE grant for this (user, client) pair so byID
	// and byPair stay consistent. Only revoke if RevokedAt is nil — byPair can
	// already point to a previously revoked grant (RevokeGrant mutates the shared
	// pointer but does not clear byPair).
	if existing, ok := s.byPair[ng.UserID+":"+ng.ClientID]; ok && existing.RevokedAt == nil {
		now := time.Now()
		existing.RevokedAt = &now
	}
	// id is a zero-padded monotonically-increasing sequence. Zero-padding
	// (8 digits) ensures lexicographic sort order matches numeric order for up
	// to 99_999_999 grants — required for the ListGrantsByUser ID tiebreaker.
	// Using a dedicated counter (not len(byID)) means IDs stay unique even if a
	// Delete method is ever added.
	s.counter++
	id := fmt.Sprintf("grant-%08d", s.counter)
	g := &Grant{
		ID:          id,
		Region:      ng.Region,
		UserID:      ng.UserID,
		ClientID:    ng.ClientID,
		PairwiseSub: ng.PairwiseSub,
		Scopes:      append([]string(nil), ng.Scopes...), // clone: caller mutation must not affect stored grant
		CreatedAt:   time.Now(),
	}
	s.byID[id] = g
	s.byPair[ng.UserID+":"+ng.ClientID] = g
	return *g, nil
}

// RevokeGrant implements GrantStore. Soft-deletes by ID.
func (s *InMemoryGrantStore) RevokeGrant(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byID[id]
	if !ok {
		return nil // idempotent
	}
	now := time.Now()
	g.RevokedAt = &now
	return nil
}

// ListGrantsByUser implements GrantStore. Returns only active (non-revoked) grants.
func (s *InMemoryGrantStore) ListGrantsByUser(_ context.Context, userID string) ([]Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Grant
	for _, g := range s.byID {
		if g.UserID == userID && g.RevokedAt == nil {
			out = append(out, *g)
		}
	}
	// Sort newest first to match the interface contract and DBGrantStore
	// ordering. byID iteration order is non-deterministic (Go map), so without
	// this the "connected apps" dashboard order would be unstable.
	// Tiebreaker on ID (lexicographic descending) stabilises the sort when two
	// grants share the same CreatedAt timestamp (possible in fast-running tests
	// where time.Now() has millisecond resolution).
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID // later sequential ID = newer grant
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}
