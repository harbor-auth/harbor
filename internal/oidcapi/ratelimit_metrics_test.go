package oidcapi_test

// Tests for the aggregate 429 rate-limit instrumentation
// (observability-metrics: abuse visibility without PII).

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harbor/harbor/internal/oidcapi"
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
	s := oidcapi.New(oidcapi.Config{Issuer: "https://eu.harbor.id"})

	// Capture before value since other tests in the package may have already
	// incremented the counter (tests share the global telemetry registry).
	before, _, _ := rateLimitSample(t, "harbor_oidc_rate_limited_total", map[string]string{
		"endpoint": "token", "region": "EU",
	})

	rec := httptest.NewRecorder()
	s.WriteRateLimited(rec, telemetry.EndpointToken, region.EU)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}

	after, keys, ok := rateLimitSample(t, "harbor_oidc_rate_limited_total", map[string]string{
		"endpoint": "token", "region": "EU",
	})
	if !ok {
		t.Fatal("rate-limit counter not emitted with endpoint+region labels")
	}
	if after-before < 1 {
		t.Errorf("rate-limit counter did not increment: before=%v after=%v", before, after)
	}
	// Assert NO per-IP or PII label ever appears on the series.
	for _, k := range keys {
		switch k {
		case "ip", "ip_address", "user_id", "client_id", "sub", "ppid", "email":
			t.Errorf("429 series carries a forbidden label %q — abuse metering must stay aggregate/PII-free", k)
		}
	}
}
