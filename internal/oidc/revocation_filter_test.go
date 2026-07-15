package oidc

import (
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
		f.Add("jti-" + string(rune('a'+i)))
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
