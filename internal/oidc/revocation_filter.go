// Package oidc revocation_filter.go provides the bloom-filter-based emergency
// JWT revocation mechanism (DESIGN.md §3.5).
//
// The RevocationFilter interface abstracts the in-process check for revoked
// JTIs. The production implementation uses a bloom filter for O(1) lookups
// with minimal memory overhead; the test implementation uses a simple map.
package oidc

import (
	"sync"

	// Bloom filter for production implementation (subsequent task).
	_ "github.com/bits-and-blooms/bloom/v3"
)

// RevocationFilter provides in-process emergency JWT revocation checks.
// The filter is checked on every token verification (~100ns overhead) and
// returns true if a JTI *might* be revoked (bloom filter semantics: false
// positives possible, false negatives impossible).
//
// On a positive result, the caller MUST confirm via DB introspection
// (GetRevokedJTI) to distinguish true positives from false positives.
//
// Thread-safety: all methods must be safe for concurrent use.
type RevocationFilter interface {
	// MightContain returns true if the JTI might be revoked. False means
	// definitely not revoked; true means possibly revoked (confirm via DB).
	MightContain(jti string) bool

	// Add marks a JTI as revoked. Called when an emergency revocation is
	// received via Redis pub/sub or management API.
	Add(jti string)

	// Remove removes a JTI from the filter. Called when a revoked JTI's
	// original JWT has expired and the entry is garbage collected.
	// Note: simple bloom filters don't support removal; counting bloom
	// filters do. The InMemoryRevocationFilter supports removal.
	Remove(jti string)

	// Rehydrate populates the filter with a batch of JTIs. Called on
	// startup to restore state from the revoked_jtis table.
	Rehydrate(jtis []string)
}

// InMemoryRevocationFilter is a simple map-based implementation for tests.
// It provides exact membership (no false positives) and supports removal.
// NOT suitable for production due to unbounded memory growth.
type InMemoryRevocationFilter struct {
	mu   sync.RWMutex
	jtis map[string]struct{}
}

// NewInMemoryRevocationFilter creates a new in-memory filter for testing.
func NewInMemoryRevocationFilter() *InMemoryRevocationFilter {
	return &InMemoryRevocationFilter{
		jtis: make(map[string]struct{}),
	}
}

// MightContain returns true if the JTI is in the filter (exact match, no
// false positives unlike bloom filter).
func (f *InMemoryRevocationFilter) MightContain(jti string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.jtis[jti]
	return ok
}

// Add marks a JTI as revoked.
func (f *InMemoryRevocationFilter) Add(jti string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jtis[jti] = struct{}{}
}

// Remove removes a JTI from the filter.
func (f *InMemoryRevocationFilter) Remove(jti string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.jtis, jti)
}

// Rehydrate populates the filter with a batch of JTIs.
func (f *InMemoryRevocationFilter) Rehydrate(jtis []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, jti := range jtis {
		f.jtis[jti] = struct{}{}
	}
}

// Len returns the number of JTIs in the filter (for testing).
func (f *InMemoryRevocationFilter) Len() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.jtis)
}

// Clear removes all JTIs from the filter. Useful for testing and for
// full rehydration (Clear + Rehydrate) on reconnection.
func (f *InMemoryRevocationFilter) Clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jtis = make(map[string]struct{})
}

// Compile-time interface check.
var _ RevocationFilter = (*InMemoryRevocationFilter)(nil)
