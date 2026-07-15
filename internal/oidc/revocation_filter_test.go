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
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				jti := "jti-concurrent"
				f.Add(jti)
				f.MightContain(jti)
			}
		}(i)
	}
	wg.Wait()

	// Should have at least one entry (may have duplicates deduplicated)
	if f.Len() < 1 {
		t.Error("expected at least one entry after concurrent adds")
	}
}
