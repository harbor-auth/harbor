package relay

import (
	"sync"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

// newTestLimiter builds a rate limiter wired to a controllable clock.
func newTestLimiter(ratePerSec float64, burst int) (*RateLimiter, *time.Time) {
	rl := NewRateLimiter(ratePerSec, burst)
	now := time.Unix(1_700_000_000, 0)
	rl.now = func() time.Time { return now }
	rl.lastGC = now
	return rl, &now
}

func TestRateLimiter_AllowsBurstThenBlocks(t *testing.T) {
	rl, _ := newTestLimiter(1, 3)

	// The first `burst` requests are permitted instantaneously.
	for i := 0; i < 3; i++ {
		if !rl.Allow("tok") {
			t.Fatalf("request %d: Allow() = false, want true (within burst)", i+1)
		}
	}
	// The next request exceeds the burst and is denied.
	if rl.Allow("tok") {
		t.Error("request 4: Allow() = true, want false (burst exhausted)")
	}
}

func TestRateLimiter_RefillsOverTime(t *testing.T) {
	rl, now := newTestLimiter(2, 2) // 2 tokens/sec, burst 2

	// Drain the bucket.
	if !rl.Allow("tok") || !rl.Allow("tok") {
		t.Fatal("expected first two requests to be allowed")
	}
	if rl.Allow("tok") {
		t.Fatal("expected third request to be denied (bucket empty)")
	}

	// After 0.5s at 2 tokens/sec, exactly one token has refilled.
	*now = now.Add(500 * time.Millisecond)
	if !rl.Allow("tok") {
		t.Error("after 0.5s refill: Allow() = false, want true")
	}
	if rl.Allow("tok") {
		t.Error("after consuming the refilled token: Allow() = true, want false")
	}
}

func TestRateLimiter_RefillCapsAtBurst(t *testing.T) {
	rl, now := newTestLimiter(1, 2)

	// Idle for a long time — tokens must not accumulate beyond burst.
	*now = now.Add(1 * time.Hour)
	if !rl.Allow("tok") || !rl.Allow("tok") {
		t.Fatal("expected burst (2) requests to be allowed after long idle")
	}
	if rl.Allow("tok") {
		t.Error("tokens accumulated beyond burst ceiling")
	}
}

func TestRateLimiter_PerKeyIndependent(t *testing.T) {
	rl, _ := newTestLimiter(1, 1)

	if !rl.Allow("a") {
		t.Fatal("key a: first request should be allowed")
	}
	// Key a is now exhausted, but key b has its own full bucket.
	if rl.Allow("a") {
		t.Error("key a: second request should be denied")
	}
	if !rl.Allow("b") {
		t.Error("key b: first request should be allowed (independent bucket)")
	}
}

func TestRateLimiter_GCEvictsStaleBuckets(t *testing.T) {
	rl, now := newTestLimiter(1, 1)
	rl.gcInterval = 0 // sweep on every call

	rl.Allow("stale")
	if got := rl.size(); got != 1 {
		t.Fatalf("size after first Allow = %d, want 1", got)
	}

	// Advance well beyond the TTL, then touch a different key. The stale bucket
	// should be evicted, leaving only the freshly-created one.
	*now = now.Add(defaultBucketTTL + time.Minute)
	rl.Allow("fresh")
	if got := rl.size(); got != 1 {
		t.Errorf("size after GC = %d, want 1 (stale bucket evicted)", got)
	}
}

func TestRateLimiter_ClampsInvalidConfig(t *testing.T) {
	// Non-positive rate/burst must clamp to a working limiter, never a no-op.
	rl := NewRateLimiter(0, 0)
	if !rl.Allow("tok") {
		t.Fatal("clamped limiter should allow the first request")
	}
	if rl.Allow("tok") {
		t.Error("clamped limiter (burst 1) should deny the second request")
	}
}

func TestRateLimiter_ConcurrentAllow(t *testing.T) {
	// The limiter must be race-free under concurrent access. With burst 100 and
	// no time advance, exactly 100 of 200 concurrent requests should succeed.
	rl, _ := newTestLimiter(1, 100)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		allowed int
	)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rl.Allow("tok") {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 100 {
		t.Errorf("allowed = %d, want 100 (burst ceiling under concurrency)", allowed)
	}
}

// counterValue gathers the facade registry and returns the value of counter
// `name` for the given exact label set, plus the label keys present (0/false if
// the series is absent).
func counterValue(t *testing.T, name string, want map[string]string) (float64, []string, bool) {
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

func TestRelayMetrics_RecordAggregateOnly(t *testing.T) {
	// Use a distinctive region value so the assertions are insensitive to any
	// counts other tests may have accrued.
	reg := region.Region("metrics-test-region")
	labels := map[string]string{"region": string(reg)}

	cases := []struct {
		name   string
		metric string
		record func(region.Region)
	}{
		{"accepted", "harbor_relay_accepted_total", recordAccepted},
		{"bounced", "harbor_relay_bounced_total", recordBounced},
		{"forwarded", "harbor_relay_forwarded_total", recordForwarded},
		{"rate_limited", "harbor_relay_rate_limited_total", recordRateLimited},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before, _, _ := counterValue(t, tc.metric, labels)
			tc.record(reg)
			after, keys, ok := counterValue(t, tc.metric, labels)
			if !ok {
				t.Fatalf("%s: counter series not emitted", tc.metric)
			}
			if after-before != 1 {
				t.Errorf("%s: delta = %v, want 1", tc.metric, after-before)
			}
			// The series must carry ONLY the region dimension — never PII.
			for _, k := range keys {
				switch k {
				case "ip", "ip_address", "user_id", "sub", "ppid", "email", "relay", "relay_address", "token":
					t.Errorf("%s carries forbidden label %q — relay metering must stay aggregate/PII-free", tc.metric, k)
				}
			}
		})
	}
}
