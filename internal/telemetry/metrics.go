package telemetry

// metrics.go is Harbor's aggregate-only, zero-PII metrics facade
// (observability-metrics REQ-002 / REQ-005). It exposes Counter, Histogram, and
// Gauge instruments that accept ONLY allow-listed Label values (see labels.go),
// so no PII or free-form label can ever reach the metrics backend.
//
// Privacy properties enforced here:
//
//   - Aggregate-only (REQ-002): the instruments are counters, histograms, and
//     gauges. No per-event unique identifier is ever retained — the facade only
//     accepts pre-bounded Label dimensions and increments/observes aggregates.
//   - Small-n suppression (REQ-005): quasi-identifier dimensions (client_id, and
//     error_code when it can single out a rare region×error_code slice) are
//     bucketed into a `suppressedValue` series until they cross a small-count
//     floor, so a label combination can never resolve to a single user at
//     count 1.
//
// The backend is prometheus/client_golang, hidden behind this facade so the
// privacy contract holds regardless of the exposition format.

import (
	"errors"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// smallCountFloor is the minimum number of observations a quasi-identifier
// label combination must accrue before it is emitted as its own metric series.
// Below the floor, quasi-identifier dimensions collapse into suppressedValue so
// no series is ever emitted at a deanonymising count of 1 (REQ-005).
const smallCountFloor = 5

// suppressedValue is the bucket that quasi-identifier label values collapse into
// until their combination crosses the small-count floor.
const suppressedValue = "other"

// registry is the facade-private Prometheus registry. Everything Harbor exposes
// goes through here, so the exposition surface is exactly the set of
// facade-constructed, allow-listed instruments — nothing else.
var registry = prometheus.NewRegistry()

// Registry returns the facade's Prometheus registry for exposition (e.g. wiring
// a scrape handler) and for tests that gather emitted samples.
func Registry() *prometheus.Registry { return registry }

// Dimension identifies an allow-listed label KEY a metric is partitioned by. It
// is derived from LabelKey, so a metric can only ever be partitioned by an
// allow-listed, non-PII dimension.
type Dimension LabelKey

const (
	DimRegion    = Dimension(KeyRegion)
	DimEndpoint  = Dimension(KeyEndpoint)
	DimOutcome   = Dimension(KeyOutcome)
	DimGrantType = Dimension(KeyGrantType)
	DimErrorCode = Dimension(KeyErrorCode)
	DimClientID  = Dimension(KeyClientID)
)

// isQuasiIdentifier reports whether a dimension can act as a quasi-identifier
// and therefore needs small-n suppression (design Decision 5 / REQ-005):
//
//   - client_id: a client with a single user makes every row effectively
//     per-user.
//   - error_code: a rare region×error_code slice can single out one event.
func isQuasiIdentifier(d Dimension) bool {
	switch LabelKey(d) {
	case KeyClientID, KeyErrorCode:
		return true
	default:
		return false
	}
}

// dimNames returns the ordered Prometheus label names for a dimension set.
func dimNames(dims []Dimension) []string {
	names := make([]string, len(dims))
	for i, d := range dims {
		names[i] = string(d)
	}
	return names
}

// orderedValues maps the supplied labels onto the metric's declared dimension
// order, producing the value slice Prometheus expects. A dimension with no
// matching label is emitted as the empty string; a label whose key is not a
// declared dimension is ignored.
func orderedValues(dims []Dimension, labels []Label) []string {
	byKey := make(map[LabelKey]string, len(labels))
	for _, l := range labels {
		byKey[l.key] = l.value
	}
	out := make([]string, len(dims))
	for i, d := range dims {
		out[i] = byKey[LabelKey(d)]
	}
	return out
}

// suppressor applies small-n suppression to quasi-identifier dimensions. It
// keeps an in-memory observation count per raw label tuple; until a tuple
// crosses the floor, its quasi-identifier dimensions are bucketed into
// suppressedValue, so no quasi-identifier series is ever emitted below the
// floor (REQ-005).
type suppressor struct {
	mu       sync.Mutex
	counts   map[string]int
	quasiIdx []int
	floor    int
}

func newSuppressor(dims []Dimension) *suppressor {
	var qi []int
	for i, d := range dims {
		if isQuasiIdentifier(d) {
			qi = append(qi, i)
		}
	}
	return &suppressor{counts: make(map[string]int), quasiIdx: qi, floor: smallCountFloor}
}

// resolve returns the label values to emit. Metrics with no quasi-identifier
// dimension are passed through unchanged; otherwise quasi-identifier values are
// bucketed until their raw combination crosses the floor.
func (s *suppressor) resolve(values []string) []string {
	if len(s.quasiIdx) == 0 {
		return values
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.Join(values, "\x1f")
	s.counts[key]++
	if s.counts[key] >= s.floor {
		return values
	}
	out := make([]string, len(values))
	copy(out, values)
	for _, idx := range s.quasiIdx {
		out[idx] = suppressedValue
	}
	return out
}

// registerOrExisting registers c, or returns the already-registered collector
// when an identical one exists. This keeps the facade robust (and testable)
// without ever panicking on a benign duplicate, while still surfacing genuine
// registration errors.
func registerOrExisting[T prometheus.Collector](c T) T {
	if err := registry.Register(c); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(T); ok {
				return existing
			}
		}
		panic(err)
	}
	return c
}

// Counter is a monotonically increasing aggregate count, partitioned by
// allow-listed dimensions.
type Counter struct {
	vec        *prometheus.CounterVec
	dims       []Dimension
	suppressor *suppressor
}

// NewCounter creates (or reuses) a counter partitioned by the given
// allow-listed dimensions.
func NewCounter(name, help string, dims ...Dimension) *Counter {
	vec := registerOrExisting(prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: name, Help: help},
		dimNames(dims),
	))
	return &Counter{vec: vec, dims: dims, suppressor: newSuppressor(dims)}
}

// Inc increments the counter by one for the given allow-listed labels.
func (c *Counter) Inc(labels ...Label) { c.Add(1, labels...) }

// Add increments the counter by delta for the given allow-listed labels.
func (c *Counter) Add(delta float64, labels ...Label) {
	values := c.suppressor.resolve(orderedValues(c.dims, labels))
	c.vec.WithLabelValues(values...).Add(delta)
}

// Histogram observes a distribution (e.g. request latency) partitioned by
// allow-listed dimensions.
type Histogram struct {
	vec        *prometheus.HistogramVec
	dims       []Dimension
	suppressor *suppressor
}

// NewHistogram creates (or reuses) a histogram partitioned by the given
// allow-listed dimensions, using Prometheus' default buckets.
func NewHistogram(name, help string, dims ...Dimension) *Histogram {
	vec := registerOrExisting(prometheus.NewHistogramVec(
		prometheus.HistogramOpts{Name: name, Help: help, Buckets: prometheus.DefBuckets},
		dimNames(dims),
	))
	return &Histogram{vec: vec, dims: dims, suppressor: newSuppressor(dims)}
}

// Observe records a single observation for the given allow-listed labels.
func (h *Histogram) Observe(v float64, labels ...Label) {
	values := h.suppressor.resolve(orderedValues(h.dims, labels))
	h.vec.WithLabelValues(values...).Observe(v)
}

// Gauge is a value that can go up and down (e.g. in-flight requests),
// partitioned by allow-listed dimensions.
type Gauge struct {
	vec        *prometheus.GaugeVec
	dims       []Dimension
	suppressor *suppressor
}

// NewGauge creates (or reuses) a gauge partitioned by the given allow-listed
// dimensions.
func NewGauge(name, help string, dims ...Dimension) *Gauge {
	vec := registerOrExisting(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: name, Help: help},
		dimNames(dims),
	))
	return &Gauge{vec: vec, dims: dims, suppressor: newSuppressor(dims)}
}

// Set sets the gauge to v for the given allow-listed labels.
func (g *Gauge) Set(v float64, labels ...Label) {
	values := g.suppressor.resolve(orderedValues(g.dims, labels))
	g.vec.WithLabelValues(values...).Set(v)
}

// Inc increments the gauge by one for the given allow-listed labels.
func (g *Gauge) Inc(labels ...Label) {
	values := g.suppressor.resolve(orderedValues(g.dims, labels))
	g.vec.WithLabelValues(values...).Inc()
}

// Dec decrements the gauge by one for the given allow-listed labels.
func (g *Gauge) Dec(labels ...Label) {
	values := g.suppressor.resolve(orderedValues(g.dims, labels))
	g.vec.WithLabelValues(values...).Dec()
}
