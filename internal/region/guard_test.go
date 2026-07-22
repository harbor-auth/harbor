package region

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
)

// TestAssertRegionAllCombinations is the table-driven core: for every ordered
// pair of known regions, a request pinned to the first region may read data in
// that same region and MUST be denied when the data lives in any other region
// (OpenSpec REQ-003). Same-region pairs succeed; cross-region pairs fail closed
// with ErrCrossRegionAccess.
//
//harbor:invariant INV-REGION-NO-CROSS-ACCESS
func TestAssertRegionAllCombinations(t *testing.T) {
	regions := []Region{EU, US, APAC}
	for _, pinned := range regions {
		for _, data := range regions {
			pinned, data := pinned, data
			name := string(pinned) + "_reads_" + string(data)
			t.Run(name, func(t *testing.T) {
				ctx := WithRegion(context.Background(), pinned)
				err := AssertRegion(ctx, data)
				if pinned == data {
					if err != nil {
						t.Fatalf("AssertRegion(pinned=%q, data=%q) = %v, want nil", pinned, data, err)
					}
					return
				}
				if !errors.Is(err, ErrCrossRegionAccess) {
					t.Fatalf("AssertRegion(pinned=%q, data=%q) = %v, want ErrCrossRegionAccess", pinned, data, err)
				}
			})
		}
	}
}

// TestAssertRegionSameRegionSucceeds spells out the happy path: a handler
// reading data resident in the pinned region proceeds (nil error).
func TestAssertRegionSameRegionSucceeds(t *testing.T) {
	ctx := WithRegion(context.Background(), EU)
	if err := AssertRegion(ctx, EU); err != nil {
		t.Fatalf("AssertRegion(EU, EU) = %v, want nil", err)
	}
}

// TestAssertRegionCrossRegionDenied is the residency-violation case: a request
// pinned to EU reading a US-resident user is denied with ErrCrossRegionAccess
// and no data is returned (the caller receives only the error).
func TestAssertRegionCrossRegionDenied(t *testing.T) {
	ctx := WithRegion(context.Background(), EU)
	err := AssertRegion(ctx, US)
	if !errors.Is(err, ErrCrossRegionAccess) {
		t.Fatalf("AssertRegion(EU, US) = %v, want ErrCrossRegionAccess", err)
	}
}

// TestAssertRegionNoPinnedRegionFailsClosed asserts that calling the guard
// without the region middleware having pinned a region fails closed with
// ErrNoRegion — the residency decision cannot be made, so access is denied.
func TestAssertRegionNoPinnedRegionFailsClosed(t *testing.T) {
	if err := AssertRegion(context.Background(), EU); !errors.Is(err, ErrNoRegion) {
		t.Fatalf("AssertRegion(no region, EU) = %v, want ErrNoRegion", err)
	}
}

// TestAssertRegionUnknownDataRegionDenied ensures an unknown/empty data region
// can never match a valid pinned region and is denied with ErrCrossRegionAccess.
func TestAssertRegionUnknownDataRegionDenied(t *testing.T) {
	ctx := WithRegion(context.Background(), EU)
	for _, bad := range []Region{"", "MARS", "eu"} {
		if err := AssertRegion(ctx, bad); !errors.Is(err, ErrCrossRegionAccess) {
			t.Fatalf("AssertRegion(EU, %q) = %v, want ErrCrossRegionAccess", bad, err)
		}
	}
}

// capturingHandler is a minimal slog.Handler that records every emitted record
// so a test can assert what was (and was not) metered.
type capturingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler      { return h }

// TestAssertRegionMetersDenial pins the guard's purity contract: a cross-region
// denial returns ErrCrossRegionAccess and the guard itself emits NO telemetry.
// Metering is the caller's (middleware) responsibility — the guard must stay
// free of any telemetry dependency so region never imports telemetry (which
// types its metric labels on region.Region; the reverse edge would be an import
// cycle). The capturing handler proves the guard writes nothing to the default
// slog sink on the denial path.
func TestAssertRegionMetersDenial(t *testing.T) {
	h := &capturingHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ctx := WithRegion(context.Background(), EU)
	if err := AssertRegion(ctx, US); !errors.Is(err, ErrCrossRegionAccess) {
		t.Fatalf("AssertRegion(EU, US) = %v, want ErrCrossRegionAccess", err)
	}

	// The pure guard must not meter: a caller does that at the middleware layer
	// using CrossRegionDeniedCode. Asserting zero records here is what keeps the
	// region -> telemetry edge from creeping back in.
	if len(h.records) != 0 {
		t.Fatalf("pure guard metered %d records, want 0 (metering is the caller's job, code=%q)", len(h.records), CrossRegionDeniedCode)
	}
}

// TestAssertRegionSuccessNotMetered ensures the happy path returns nil and, like
// the denial path, emits no telemetry from the guard itself.
func TestAssertRegionSuccessNotMetered(t *testing.T) {
	h := &capturingHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ctx := WithRegion(context.Background(), EU)
	if err := AssertRegion(ctx, EU); err != nil {
		t.Fatalf("AssertRegion(EU, EU) = %v, want nil", err)
	}
	if len(h.records) != 0 {
		t.Fatalf("success path metered %d records, want 0", len(h.records))
	}
}
