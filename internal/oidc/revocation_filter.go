// Package oidc revocation_filter.go provides the bloom-filter-based emergency
// JWT revocation mechanism (DESIGN.md §3.5).
//
// The RevocationFilter interface abstracts the in-process check for revoked
// JTIs. The production implementation uses a bloom filter for O(1) lookups
// with minimal memory overhead; the test implementation uses a simple map.
package oidc

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/bits-and-blooms/bloom/v3"
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

// BloomRevocationFilter wraps a bloom filter with thread-safe access for
// production use. Uses bloom.NewWithEstimates for optimal sizing based on
// expected capacity and target false-positive rate.
//
// IMPORTANT: Standard bloom filters do NOT support removal. The Remove method
// is a no-op. For production use with removal support, use a counting bloom
// filter or accept that removed JTIs remain in the filter until rehydration.
type BloomRevocationFilter struct {
	mu     sync.RWMutex
	filter *bloom.BloomFilter

	// Configuration for rebuilding the filter on Clear/Rehydrate.
	capacity uint
	fpRate   float64
}

// DefaultBloomCapacity is the default expected number of revoked JTIs.
// 10,000 active revocations with 1/1M FP rate requires ~240KB.
const DefaultBloomCapacity = 10000

// DefaultBloomFPRate is the default false-positive rate (1 in 1,000,000).
const DefaultBloomFPRate = 0.000001

// NewBloomRevocationFilter creates a new bloom filter with the given capacity
// and false-positive rate. Use DefaultBloomCapacity and DefaultBloomFPRate
// for standard production configuration.
func NewBloomRevocationFilter(capacity uint, fpRate float64) *BloomRevocationFilter {
	return &BloomRevocationFilter{
		filter:   bloom.NewWithEstimates(capacity, fpRate),
		capacity: capacity,
		fpRate:   fpRate,
	}
}

// MightContain returns true if the JTI might be revoked. Uses read lock for
// concurrent access (~100ns overhead).
func (f *BloomRevocationFilter) MightContain(jti string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.filter.TestString(jti)
}

// Add marks a JTI as revoked. Uses write lock.
func (f *BloomRevocationFilter) Add(jti string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.filter.AddString(jti)
}

// Remove is a no-op for standard bloom filters (they don't support removal).
// The JTI will remain in the filter until the next Clear+Rehydrate cycle.
// This is acceptable because false positives only trigger a DB lookup, and
// expired JTIs are garbage-collected from the DB anyway.
func (f *BloomRevocationFilter) Remove(jti string) {
	// No-op: standard bloom filters cannot remove elements.
	// The filter will be rebuilt on the next rehydration cycle.
}

// Rehydrate clears the filter and repopulates it with the given JTIs.
// This is called on startup and periodically to remove stale entries.
func (f *BloomRevocationFilter) Rehydrate(jtis []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Create a fresh filter to remove any stale entries.
	f.filter = bloom.NewWithEstimates(f.capacity, f.fpRate)
	for _, jti := range jtis {
		f.filter.AddString(jti)
	}
}

// Clear resets the filter to empty state.
func (f *BloomRevocationFilter) Clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.filter = bloom.NewWithEstimates(f.capacity, f.fpRate)
}

// EstimatedCount returns the approximate number of elements in the filter.
// This is useful for monitoring and debugging.
func (f *BloomRevocationFilter) EstimatedCount() uint32 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.filter.ApproximatedSize()
}

// Compile-time interface checks.
var _ RevocationFilter = (*InMemoryRevocationFilter)(nil)
var _ RevocationFilter = (*BloomRevocationFilter)(nil)

// ActiveJTILister lists active (non-expired) revoked JTIs from the database.
// At wiring time, wrap *clients.DBRevokedJTIStore with an adapter:
//
//	type jtiListerAdapter struct{ store *clients.DBRevokedJTIStore }
//	func (a jtiListerAdapter) ListActiveJTIs(ctx context.Context) ([]string, error) {
//		rows, err := a.store.ListActive(ctx)
//		if err != nil { return nil, err }
//		jtis := make([]string, len(rows))
//		for i, r := range rows { jtis[i] = r.JTI }
//		return jtis, nil
//	}
type ActiveJTILister interface {
	ListActiveJTIs(ctx context.Context) ([]string, error)
}

// RehydrateFilter loads all active revoked JTIs from the database and
// populates the filter. This MUST be called on startup before accepting
// traffic to ensure emergency revocations survive replica restarts.
//
// On success, returns the number of JTIs loaded. On error, the filter is
// left unchanged (fail-closed: better to have stale data than crash).
//
// Usage (in main or startup hook):
//
//	n, err := oidc.RehydrateFilter(ctx, lister, filter, logger)
//	if err != nil {
//		logger.Error("failed to rehydrate revocation filter", "error", err)
//		// Continue with empty filter — tokens will be checked against DB
//	}
//	logger.Info("revocation filter rehydrated", "count", n)
func RehydrateFilter(ctx context.Context, lister ActiveJTILister, filter RevocationFilter, logger *slog.Logger) (int, error) {
	if lister == nil || filter == nil {
		return 0, nil
	}
	if logger == nil {
		logger = slog.Default()
	}

	jtis, err := lister.ListActiveJTIs(ctx)
	if err != nil {
		return 0, fmt.Errorf("rehydrate filter: list active: %w", err)
	}

	filter.Rehydrate(jtis)
	logger.Info("revocation filter rehydrated", "count", len(jtis))
	return len(jtis), nil
}
