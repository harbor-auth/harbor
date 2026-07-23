package mgmtapi

import (
	"context"
	"sync"

	"github.com/harbor-auth/harbor/internal/relay"
)

// InMemoryBYODomainStore provides an in-memory implementation of BYODomainStore
// for development and testing. This store is NOT persistent — all data is lost
// when the process restarts.
//
// IMPORTANT: This is a dev scaffold only. Production deployments should use
// a database-backed store (follow-up work). The in-memory store is useful for:
//   - Local development without a database
//   - Unit testing the HTTP handlers
//   - Integration testing the relay wiring
//
// Thread-safety: All methods are safe for concurrent use via sync.RWMutex.
type InMemoryBYODomainStore struct {
	mu      sync.RWMutex
	domains map[string]*relay.BYODomain // keyed by domain name
}

// Compile-time proof of interface satisfaction.
var _ BYODomainStore = (*InMemoryBYODomainStore)(nil)

// NewInMemoryBYODomainStore creates a new in-memory BYO-domain store.
func NewInMemoryBYODomainStore() *InMemoryBYODomainStore {
	return &InMemoryBYODomainStore{
		domains: make(map[string]*relay.BYODomain),
	}
}

// CreateDomain persists a new BYO-domain challenge. Returns ErrDomainAlreadyExists
// if a domain with the same name already exists (regardless of owner).
func (s *InMemoryBYODomainStore) CreateDomain(_ context.Context, domain *relay.BYODomain) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.domains[domain.Domain]; exists {
		return relay.ErrDomainAlreadyExists
	}

	// Store a copy to prevent external mutation
	stored := *domain
	s.domains[domain.Domain] = &stored
	return nil
}

// GetDomainByName retrieves a domain by its name and user ID. Returns
// ErrDomainNotFound if the domain doesn't exist or belongs to a different user.
func (s *InMemoryBYODomainStore) GetDomainByName(_ context.Context, userID, domain string) (*relay.BYODomain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	d, ok := s.domains[domain]
	if !ok {
		return nil, relay.ErrDomainNotFound
	}

	// Verify ownership — return not-found to avoid leaking existence
	if d.UserID.String() != userID {
		return nil, relay.ErrDomainNotFound
	}

	// Return a copy to prevent external mutation
	result := *d
	return &result, nil
}

// ListDomainsByUser returns all BYO-domains for a user. Returns an empty slice
// (not nil) if the user has no domains.
func (s *InMemoryBYODomainStore) ListDomainsByUser(_ context.Context, userID string) ([]*relay.BYODomain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*relay.BYODomain
	for _, d := range s.domains {
		if d.UserID.String() == userID {
			// Return a copy to prevent external mutation
			domainCopy := *d
			result = append(result, &domainCopy)
		}
	}

	// Return empty slice, not nil, for consistent JSON serialization
	if result == nil {
		result = []*relay.BYODomain{}
	}
	return result, nil
}

// UpdateDomainState updates the state of a domain. Returns ErrDomainNotFound
// if the domain doesn't exist.
func (s *InMemoryBYODomainStore) UpdateDomainState(_ context.Context, domainID string, state relay.BYODomainState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, d := range s.domains {
		if d.ID.String() == domainID {
			d.State = state
			return nil
		}
	}
	return relay.ErrDomainNotFound
}

// DeleteDomain removes a domain by ID. Returns ErrDomainNotFound if the domain
// doesn't exist.
func (s *InMemoryBYODomainStore) DeleteDomain(_ context.Context, domainID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for name, d := range s.domains {
		if d.ID.String() == domainID {
			delete(s.domains, name)
			return nil
		}
	}
	return relay.ErrDomainNotFound
}
