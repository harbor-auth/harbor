package region

import (
	"context"
	"errors"
	"testing"
)

func TestWithRegionRoundTrip(t *testing.T) {
	for _, r := range []Region{EU, US, APAC} {
		t.Run(string(r), func(t *testing.T) {
			ctx := WithRegion(context.Background(), r)
			got, err := FromContext(ctx)
			if err != nil {
				t.Fatalf("FromContext after WithRegion(%q) unexpected error: %v", r, err)
			}
			if got != r {
				t.Fatalf("FromContext = %q, want %q", got, r)
			}
		})
	}
}

// TestFromContextFailsClosedWhenUnset asserts the fail-closed invariant: a
// context with no pinned region yields ErrNoRegion (OpenSpec REQ-002).
func TestFromContextFailsClosedWhenUnset(t *testing.T) {
	got, err := FromContext(context.Background())
	if !errors.Is(err, ErrNoRegion) {
		t.Fatalf("FromContext(empty) error = %v, want ErrNoRegion", err)
	}
	if got != "" {
		t.Fatalf("FromContext(empty) = %q, want empty region", got)
	}
}

// TestFromContextRejectsUnknownRegion ensures a malformed pin (an empty or
// unknown Region value) is treated as unset and fails closed rather than being
// mistaken for a valid residency decision.
func TestFromContextRejectsUnknownRegion(t *testing.T) {
	for _, bad := range []Region{"", "MARS", "eu"} {
		ctx := context.WithValue(context.Background(), regionKey, bad)
		if got, err := FromContext(ctx); !errors.Is(err, ErrNoRegion) {
			t.Fatalf("FromContext(region=%q) = %q, err=%v; want ErrNoRegion", bad, got, err)
		}
	}
}

// TestFromContextIgnoresForeignValue ensures a value stored under a different
// (foreign) context key does not satisfy FromContext — the private key type
// prevents collisions.
func TestFromContextIgnoresForeignValue(t *testing.T) {
	type otherKey struct{}
	ctx := context.WithValue(context.Background(), otherKey{}, EU)
	if _, err := FromContext(ctx); !errors.Is(err, ErrNoRegion) {
		t.Fatalf("FromContext with foreign key error = %v, want ErrNoRegion", err)
	}
}
