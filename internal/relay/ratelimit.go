package relay

import (
	"math"
	"sync"
	"time"
)

// Rate-limiter defaults. Idle buckets are swept periodically so memory stays
// bounded by the number of *recently active* relay addresses, not the total
// number of addresses ever seen.
const (
	// defaultBucketTTL is how long an idle bucket is retained before it is
	// eligible for garbage collection. A dropped bucket is indistinguishable
	// from a fresh (full) one, so eviction never lets a sender exceed its rate.
	defaultBucketTTL = 10 * time.Minute
	// defaultGCInterval is the minimum wall-clock spacing between sweeps.
	defaultGCInterval = time.Minute
)

// tokenBucket is a single classic token bucket: it holds a fractional number of
// tokens that refill continuously up to a burst ceiling.
type tokenBucket struct {
	tokens float64   // currently available tokens
	last   time.Time // last time tokens were refilled
}

// RateLimiter enforces a per-relay-address token-bucket rate limit. Each relay
// token gets its own bucket that refills at `rate` tokens/second up to `burst`
// tokens. It is safe for concurrent use across SMTP sessions.
//
// Privacy note: the limiter keys on the opaque relay token only. It keeps no
// per-user behavioural history — a bucket holds nothing but a token count and a
// timestamp, and idle buckets are garbage-collected.
type RateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*tokenBucket
	rate       float64 // tokens added per second
	burst      float64 // maximum tokens (bucket capacity)
	ttl        time.Duration
	gcInterval time.Duration
	lastGC     time.Time

	// now returns the current time; overridable in tests for a deterministic
	// clock.
	now func() time.Time
}

// NewRateLimiter creates a per-address rate limiter allowing `burst` messages
// instantaneously and refilling at `ratePerSec` messages per second. Both
// arguments are clamped to sane minimums so a mis-configuration cannot disable
// the limiter entirely.
func NewRateLimiter(ratePerSec float64, burst int) *RateLimiter {
	if ratePerSec <= 0 {
		ratePerSec = 1
	}
	if burst <= 0 {
		burst = 1
	}
	now := time.Now
	return &RateLimiter{
		buckets:    make(map[string]*tokenBucket),
		rate:       ratePerSec,
		burst:      float64(burst),
		ttl:        defaultBucketTTL,
		gcInterval: defaultGCInterval,
		lastGC:     now(),
		now:        now,
	}
}

// Allow reports whether one message is permitted for the given relay token,
// consuming a token when it returns true. It returns false when the address has
// exhausted its bucket (i.e., is being rate limited).
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	rl.gcLocked(now)

	b, ok := rl.buckets[key]
	if !ok {
		b = &tokenBucket{tokens: rl.burst, last: now}
		rl.buckets[key] = b
	}

	// Refill based on elapsed time since the bucket was last touched.
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(rl.burst, b.tokens+elapsed*rl.rate)
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens -= 1
		return true
	}
	return false
}

// gcLocked evicts buckets that have been idle longer than ttl. It must be called
// with rl.mu held. Sweeps are rate-limited by gcInterval so the common path stays
// cheap. Evicting an idle bucket is safe: a full bucket that is recreated on the
// next request is identical to the one that was dropped.
func (rl *RateLimiter) gcLocked(now time.Time) {
	if now.Sub(rl.lastGC) < rl.gcInterval {
		return
	}
	rl.lastGC = now
	for k, b := range rl.buckets {
		if now.Sub(b.last) > rl.ttl {
			delete(rl.buckets, k)
		}
	}
}

// size returns the number of live buckets. Used by tests to assert GC behaviour.
func (rl *RateLimiter) size() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.buckets)
}
