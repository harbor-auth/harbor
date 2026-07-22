package telemetry_test

// Tests for the aggregate-only, zero-PII metrics facade
// (observability-metrics REQ-002 / REQ-003 / REQ-005).

import (
	"testing"

	dto "github.com/prometheus/client_model/go"

	"github.com/harbor/harbor/internal/region"
	"github.com/harbor/harbor/internal/telemetry"
)

// sampleValue gathers the facade registry and returns the counter/gauge value
// for the metric `name` whose label set exactly equals want. It returns
// (0, false) when no such series exists — used to assert a series was NOT
// emitted (e.g. a suppressed client_id).
func sampleValue(t *testing.T, name string, want map[string]string) (float64, bool) {
	t.Helper()
	fams, err := telemetry.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, fam := range fams {
		if fam.GetName() != name {
			continue
		}
		for _, m := range fam.GetMetric() {
			if !labelsEqual(m.GetLabel(), want) {
				continue
			}
			switch {
			case m.Counter != nil:
				return m.Counter.GetValue(), true
			case m.Gauge != nil:
				return m.Gauge.GetValue(), true
			}
		}
	}
	return 0, false
}

// histogramCount gathers the sample count of a histogram series matching want.
func histogramCount(t *testing.T, name string, want map[string]string) (uint64, bool) {
	t.Helper()
	fams, err := telemetry.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, fam := range fams {
		if fam.GetName() != name {
			continue
		}
		for _, m := range fam.GetMetric() {
			if m.Histogram != nil && labelsEqual(m.GetLabel(), want) {
				return m.Histogram.GetSampleCount(), true
			}
		}
	}
	return 0, false
}

func labelsEqual(pairs []*dto.LabelPair, want map[string]string) bool {
	if len(pairs) != len(want) {
		return false
	}
	for _, p := range pairs {
		if want[p.GetName()] != p.GetValue() {
			return false
		}
	}
	return true
}

func TestCounterIncrementsWithAllowListedLabels(t *testing.T) {
	c := telemetry.NewCounter("test_counter_total", "help",
		telemetry.DimEndpoint, telemetry.DimOutcome)

	c.Inc(telemetry.Endpoint(telemetry.EndpointToken), telemetry.Outcome(telemetry.OutcomeSuccess))
	c.Add(2, telemetry.Endpoint(telemetry.EndpointToken), telemetry.Outcome(telemetry.OutcomeSuccess))

	got, ok := sampleValue(t, "test_counter_total", map[string]string{
		"endpoint": "token", "outcome": "success",
	})
	if !ok {
		t.Fatal("counter series not emitted")
	}
	if got != 3 {
		t.Errorf("counter = %v, want 3", got)
	}
}

func TestHistogramObservesWithAllowListedLabels(t *testing.T) {
	h := telemetry.NewHistogram("test_latency_seconds", "help", telemetry.DimEndpoint)

	h.Observe(0.01, telemetry.Endpoint(telemetry.EndpointAuthorize))
	h.Observe(0.2, telemetry.Endpoint(telemetry.EndpointAuthorize))

	count, ok := histogramCount(t, "test_latency_seconds", map[string]string{"endpoint": "authorize"})
	if !ok {
		t.Fatal("histogram series not emitted")
	}
	if count != 2 {
		t.Errorf("histogram sample count = %d, want 2", count)
	}
}

func TestGaugeSetIncDec(t *testing.T) {
	g := telemetry.NewGauge("test_inflight", "help", telemetry.DimEndpoint)
	lbl := telemetry.Endpoint(telemetry.EndpointToken)

	g.Set(5, lbl)
	g.Inc(lbl)
	g.Dec(lbl)
	g.Dec(lbl)

	got, ok := sampleValue(t, "test_inflight", map[string]string{"endpoint": "token"})
	if !ok {
		t.Fatal("gauge series not emitted")
	}
	if got != 4 {
		t.Errorf("gauge = %v, want 4", got)
	}
}

// TestPerRegionAggregation asserts region is a first-class aggregate dimension
// (REQ-003): per-region counters accumulate independently with no user join.
func TestPerRegionAggregation(t *testing.T) {
	c := telemetry.NewCounter("test_region_requests_total", "help", telemetry.DimRegion)

	c.Inc(telemetry.Region(region.EU))
	c.Inc(telemetry.Region(region.EU))
	c.Inc(telemetry.Region(region.US))

	if got, ok := sampleValue(t, "test_region_requests_total", map[string]string{"region": "EU"}); !ok || got != 2 {
		t.Errorf("EU counter = %v (ok=%v), want 2", got, ok)
	}
	if got, ok := sampleValue(t, "test_region_requests_total", map[string]string{"region": "US"}); !ok || got != 1 {
		t.Errorf("US counter = %v (ok=%v), want 1", got, ok)
	}
}

// TestClientIDSmallNSuppression asserts REQ-005: a client_id whose combination
// stays below the small-count floor is bucketed into the aggregate "other"
// series and its own client_id series is NOT emitted, so a single-user client
// can never resolve to a per-user row.
func TestClientIDSmallNSuppression(t *testing.T) {
	c := telemetry.NewCounter("test_client_requests_total", "help", telemetry.DimClientID)
	const rare = "single-user-client"

	// Three increments — below the floor of 5.
	for i := 0; i < 3; i++ {
		c.Inc(telemetry.ClientID(rare))
	}

	if _, ok := sampleValue(t, "test_client_requests_total", map[string]string{"client_id": rare}); ok {
		t.Errorf("rare client_id series was emitted below the small-count floor — deanonymisation risk")
	}
	if got, ok := sampleValue(t, "test_client_requests_total", map[string]string{"client_id": "other"}); !ok || got != 3 {
		t.Errorf("suppressed \"other\" bucket = %v (ok=%v), want 3", got, ok)
	}
}

// TestClientIDEmittedAboveFloor asserts the complement of REQ-005: once a
// client_id crosses the small-count floor it becomes its own series, retaining
// legitimate per-client operational insight above the floor.
func TestClientIDEmittedAboveFloor(t *testing.T) {
	c := telemetry.NewCounter("test_client_floor_total", "help", telemetry.DimClientID)
	const busy = "busy-client"

	// Seven increments: the first four bucket into "other", the fifth crosses
	// the floor and the remaining ones land on the real client_id series.
	for i := 0; i < 7; i++ {
		c.Inc(telemetry.ClientID(busy))
	}

	if got, ok := sampleValue(t, "test_client_floor_total", map[string]string{"client_id": busy}); !ok || got != 3 {
		t.Errorf("above-floor client_id series = %v (ok=%v), want 3", got, ok)
	}
	if got, ok := sampleValue(t, "test_client_floor_total", map[string]string{"client_id": "other"}); !ok || got != 4 {
		t.Errorf("below-floor \"other\" bucket = %v (ok=%v), want 4", got, ok)
	}
}

// TestNonQuasiIdentifierNotSuppressed asserts suppression applies only to
// quasi-identifier dimensions: a plain region counter is emitted immediately,
// never bucketed into "other".
func TestNonQuasiIdentifierNotSuppressed(t *testing.T) {
	c := telemetry.NewCounter("test_no_suppress_total", "help", telemetry.DimRegion)
	c.Inc(telemetry.Region(region.APAC))

	if got, ok := sampleValue(t, "test_no_suppress_total", map[string]string{"region": "APAC"}); !ok || got != 1 {
		t.Errorf("region series = %v (ok=%v), want 1 (must not be suppressed)", got, ok)
	}
}
