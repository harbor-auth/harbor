package mgmtapi_test

// Tests for the aggregate 429 rate-limit instrumentation
// (observability-metrics: abuse visibility without PII).

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harbor/harbor/internal/mgmtapi"
	"github.com/harbor/harbor/internal/region"
	"github.com/harbor/harbor/internal/telemetry"
)

// rateLimitSample gathers the facade registry and returns the counter value for
// metric `name` whose label set exactly equals want, plus its label keys.
func rateLimitSample(t *testing.T, name string, want map[string]string) (float64, []string, bool) {
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
			keys := make([]string, 0, len(m.GetLabel()))
			match := len(m.GetLabel()) == len(want)
			for _, p := range m.GetLabel() {
				keys = append(keys, p.GetName())
				if want[p.GetName()] != p.GetValue() {
					match = false
				}
			}
			if match && m.Counter != nil {
				return m.Counter.GetValue(), keys, true
			}
		}
	}
	return 0, nil, false
}

func TestWriteRateLimited_Returns429AndAggregateMetric(t *testing.T) {
	s := mgmtapi.New(nil, nil)
	rec := httptest.NewRecorder()

	s.WriteRateLimited(rec, telemetry.EndpointEnroll, region.US)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}

	val, keys, ok := rateLimitSample(t, "harbor_mgmt_rate_limited_total", map[string]string{
		"endpoint": "enroll", "region": "US",
	})
	if !ok {
		t.Fatal("rate-limit counter not emitted with endpoint+region labels")
	}
	if val != 1 {
		t.Errorf("rate-limit counter = %v, want 1", val)
	}
	for _, k := range keys {
		switch k {
		case "ip", "ip_address", "user_id", "client_id", "sub", "ppid", "email":
			t.Errorf("429 series carries a forbidden label %q — abuse metering must stay aggregate/PII-free", k)
		}
	}
}
