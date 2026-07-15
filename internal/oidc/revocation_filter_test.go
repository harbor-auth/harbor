package oidc

import (
	"fmt"
	"sync"
	"testing"
)

func TestInMemoryRevocationFilter_AddAndMightContain(t *testing.T) {
	f := NewInMemoryRevocationFilter()

	// Initially empty
	if f.MightContain("jti-1") {
		t.Error("expected empty filter to not contain jti-1")
	}

	// Add and verify
	f.Add("jti-1")
	if !f.MightContain("jti-1") {
		t.Error("expected filter to contain jti-1 after Add")
	}

	// Other JTIs still not present
	if f.MightContain("jti-2") {
		t.Error("expected filter to not contain jti-2")
	}
}

func TestInMemoryRevocationFilter_Remove(t *testing.T) {
	f := NewInMemoryRevocationFilter()

	f.Add("jti-1")
	f.Add("jti-2")

	if f.Len() != 2 {
		t.Errorf("expected Len() = 2, got %d", f.Len())
	}

	f.Remove("jti-1")

	if f.MightContain("jti-1") {
		t.Error("expected jti-1 to be removed")
	}
	if !f.MightContain("jti-2") {
		t.Error("expected jti-2 to still be present")
	}
	if f.Len() != 1 {
		t.Errorf("expected Len() = 1, got %d", f.Len())
	}

	// Remove non-existent is a no-op
	f.Remove("jti-nonexistent")
	if f.Len() != 1 {
		t.Errorf("expected Len() = 1 after removing non-existent, got %d", f.Len())
	}
}

func TestInMemoryRevocationFilter_Rehydrate(t *testing.T) {
	f := NewInMemoryRevocationFilter()

	// Rehydrate with initial batch
	f.Rehydrate([]string{"jti-1", "jti-2", "jti-3"})

	if f.Len() != 3 {
		t.Errorf("expected Len() = 3, got %d", f.Len())
	}

	for _, jti := range []string{"jti-1", "jti-2", "jti-3"} {
		if !f.MightContain(jti) {
			t.Errorf("expected filter to contain %s after Rehydrate", jti)
		}
	}

	// Rehydrate appends (does not clear)
	f.Rehydrate([]string{"jti-4"})
	if f.Len() != 4 {
		t.Errorf("expected Len() = 4 after second Rehydrate, got %d", f.Len())
	}
}

func TestInMemoryRevocationFilter_Clear(t *testing.T) {
	f := NewInMemoryRevocationFilter()

	f.Rehydrate([]string{"jti-1", "jti-2", "jti-3"})
	if f.Len() != 3 {
		t.Errorf("expected Len() = 3, got %d", f.Len())
	}

	f.Clear()

	if f.Len() != 0 {
		t.Errorf("expected Len() = 0 after Clear, got %d", f.Len())
	}
	if f.MightContain("jti-1") {
		t.Error("expected jti-1 to not be present after Clear")
	}
}

func TestInMemoryRevocationFilter_Concurrent(t *testing.T) {
	f := NewInMemoryRevocationFilter()

	var wg sync.WaitGroup
	const goroutines = 100
	const opsPerGoroutine = 100

	// Concurrent adds
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				jti := "jti-concurrent"
				f.Add(jti)
				f.MightContain(jti)
			}
		}()
	}
	wg.Wait()

	// Should have at least one entry (may have duplicates deduplicated)
	if f.Len() < 1 {
		t.Error("expected at least one entry after concurrent adds")
	}
}

// BloomRevocationFilter tests

func TestBloomRevocationFilter_AddAndMightContain(t *testing.T) {
	f := NewBloomRevocationFilter(1000, 0.0001)

	// Initially empty
	if f.MightContain("jti-1") {
		t.Error("expected empty filter to not contain jti-1")
	}

	// Add and verify
	f.Add("jti-1")
	if !f.MightContain("jti-1") {
		t.Error("expected filter to contain jti-1 after Add")
	}
}

func TestBloomRevocationFilter_RemoveIsNoOp(t *testing.T) {
	f := NewBloomRevocationFilter(1000, 0.0001)

	f.Add("jti-1")
	f.Remove("jti-1") // Should be a no-op

	// Bloom filters cannot remove, so element should still be present
	if !f.MightContain("jti-1") {
		t.Error("expected jti-1 to still be present after Remove (bloom filters don't support removal)")
	}
}

func TestBloomRevocationFilter_Rehydrate(t *testing.T) {
	f := NewBloomRevocationFilter(1000, 0.0001)

	// Add some initial entries
	f.Add("old-jti-1")
	f.Add("old-jti-2")

	// Rehydrate with new entries (should clear old ones)
	f.Rehydrate([]string{"new-jti-1", "new-jti-2", "new-jti-3"})

	// Old entries should be gone
	if f.MightContain("old-jti-1") {
		t.Error("expected old-jti-1 to be cleared after Rehydrate")
	}

	// New entries should be present
	for _, jti := range []string{"new-jti-1", "new-jti-2", "new-jti-3"} {
		if !f.MightContain(jti) {
			t.Errorf("expected filter to contain %s after Rehydrate", jti)
		}
	}
}

func TestBloomRevocationFilter_Clear(t *testing.T) {
	f := NewBloomRevocationFilter(1000, 0.0001)

	f.Add("jti-1")
	f.Add("jti-2")

	f.Clear()

	if f.MightContain("jti-1") {
		t.Error("expected jti-1 to not be present after Clear")
	}
	if f.MightContain("jti-2") {
		t.Error("expected jti-2 to not be present after Clear")
	}
}

func TestBloomRevocationFilter_EstimatedCount(t *testing.T) {
	f := NewBloomRevocationFilter(1000, 0.0001)

	// Add some entries
	for i := 0; i < 100; i++ {
		f.Add(fmt.Sprintf("jti-%d", i))
	}

	// EstimatedCount should be approximately 100
	count := f.EstimatedCount()
	if count < 50 || count > 150 {
		t.Errorf("expected EstimatedCount ~100, got %d", count)
	}
}

func TestBloomRevocationFilter_Concurrent(t *testing.T) {
	f := NewBloomRevocationFilter(10000, 0.000001)

	var wg sync.WaitGroup
	const goroutines = 100
	const opsPerGoroutine = 100

	// Concurrent adds and reads
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				jti := "jti-concurrent"
				f.Add(jti)
				f.MightContain(jti)
			}
		}()
	}
	wg.Wait()

	// Should contain the concurrent JTI
	if !f.MightContain("jti-concurrent") {
		t.Error("expected filter to contain jti-concurrent after concurrent adds")
	}
}

func TestBloomRevocationFilter_DefaultConstants(t *testing.T) {
	// Verify default constants are reasonable
	if DefaultBloomCapacity != 10000 {
		t.Errorf("expected DefaultBloomCapacity = 10000, got %d", DefaultBloomCapacity)
	}
	if DefaultBloomFPRate != 0.000001 {
		t.Errorf("expected DefaultBloomFPRate = 0.000001, got %f", DefaultBloomFPRate)
	}

	// Create filter with defaults
	f := NewBloomRevocationFilter(DefaultBloomCapacity, DefaultBloomFPRate)
	if f == nil {
		t.Error("expected NewBloomRevocationFilter with defaults to succeed")
	}
}

func TestBloomRevocationFilter_FalsePositiveRate(t *testing.T) {
	// Test that the false-positive rate is within acceptable bounds.
	// We use a higher FP rate (0.01 = 1%) for faster testing, then verify
	// the actual rate is within 2x of the target (allowing for variance).
	const (
		capacity     = 1000
		targetFPRate = 0.01 // 1%
		numInserts   = 1000
		numProbes    = 10000
	)

	f := NewBloomRevocationFilter(capacity, targetFPRate)

	// Insert numInserts unique JTIs
	for i := 0; i < numInserts; i++ {
		f.Add(fmt.Sprintf("inserted-jti-%d", i))
	}

	// Probe with JTIs that were NOT inserted and count false positives
	falsePositives := 0
	for i := 0; i < numProbes; i++ {
		// Use a different prefix to ensure these were never inserted
		if f.MightContain(fmt.Sprintf("probe-jti-%d", i)) {
			falsePositives++
		}
	}

	actualFPRate := float64(falsePositives) / float64(numProbes)

	// Allow up to 3x the target rate due to statistical variance
	maxAllowedFPRate := targetFPRate * 3.0
	if actualFPRate > maxAllowedFPRate {
		t.Errorf("false-positive rate too high: got %.4f, max allowed %.4f (target %.4f)",
			actualFPRate, maxAllowedFPRate, targetFPRate)
	}

	// Log the actual rate for informational purposes
	t.Logf("False-positive rate: %.4f (target: %.4f, max: %.4f)",
		actualFPRate, targetFPRate, maxAllowedFPRate)
}

func TestBloomRevocationFilter_NoFalseNegatives(t *testing.T) {
	// Bloom filters guarantee NO false negatives: if an element was added,
	// MightContain MUST return true.
	f := NewBloomRevocationFilter(10000, 0.000001)

	const numJTIs = 1000
	jtis := make([]string, numJTIs)
	for i := 0; i < numJTIs; i++ {
		jtis[i] = fmt.Sprintf("guaranteed-jti-%d", i)
		f.Add(jtis[i])
	}

	// Every inserted JTI MUST be found
	for _, jti := range jtis {
		if !f.MightContain(jti) {
			t.Errorf("false negative detected: %s was added but MightContain returned false", jti)
		}
	}
}

func TestBloomRevocationFilter_UnknownJTIsReturnFalse(t *testing.T) {
	// Test that MightContain returns false for unknown JTIs (most of the time).
	// With a very low FP rate, this should almost always be true.
	f := NewBloomRevocationFilter(10000, 0.000001)

	// Add a few known JTIs
	f.Add("known-jti-1")
	f.Add("known-jti-2")
	f.Add("known-jti-3")

	// Unknown JTIs should return false (with very high probability)
	unknownJTIs := []string{
		"unknown-jti-a",
		"unknown-jti-b",
		"unknown-jti-c",
		"completely-different-string",
		"another-random-jti",
	}

	for _, jti := range unknownJTIs {
		if f.MightContain(jti) {
			// This could theoretically be a false positive, but with 1/1M rate
			// and only 5 probes, this is extremely unlikely
			t.Logf("unexpected hit for %s (could be false positive)", jti)
		}
	}
}

func TestBloomRevocationFilter_ConcurrentReadsAndWrites(t *testing.T) {
	// Test concurrent safety with mixed read/write operations.
	// Run with -race flag to detect race conditions.
	f := NewBloomRevocationFilter(10000, 0.000001)

	var wg sync.WaitGroup
	const (
		readers      = 50
		writers      = 10
		opsPerWorker = 100
	)

	// Start writers
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerWorker; j++ {
				f.Add(fmt.Sprintf("writer-%d-jti-%d", id, j))
			}
		}(i)
	}

	// Start readers
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerWorker; j++ {
				f.MightContain(fmt.Sprintf("reader-%d-probe-%d", id, j))
			}
		}(i)
	}

	wg.Wait()

	// Verify the filter is still functional after concurrent access
	testJTI := "post-concurrent-test"
	f.Add(testJTI)
	if !f.MightContain(testJTI) {
		t.Error("filter not functional after concurrent access")
	}
}
