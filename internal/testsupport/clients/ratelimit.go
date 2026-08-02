// Package clientstest provides client-layer collaborators for external tests.
package clientstest

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/harbor-auth/harbor/internal/clients"
)

var _ clients.RateLimiter = (*MemoryRateLimiter)(nil)

// memWindow holds the sliding-window counters for a single key. windowStart is
// the start (unix ms) of the window `current` counts against; `previous` counts
// the window immediately before it, used for the sliding-window overlap.
type memWindow struct {
	windowStart int64
	current     int
	previous    int
}

// MemoryRateLimiter is an isolated test fixture. It mirrors the sliding-window
// semantics of RedisRateLimiter but keeps all state in a mutex-guarded map.
//
// Stale per-key entries are pruned lazily on access and periodically swept, so
// memory stays bounded to roughly the set of recently-active keys.
type MemoryRateLimiter struct {
	mu         sync.Mutex
	entries    map[string]*memWindow
	limit      int
	window     time.Duration
	lastSweep  time.Time
	sweepEvery time.Duration
	// nowFn is an injectable clock, overridden in tests for deterministic
	// window advancement; defaults to time.Now.
	nowFn func() time.Time
}

// NewMemoryRateLimiter creates an in-memory rate limiter with the same config
// contract as NewRedisRateLimiter (KeyPrefix is unused here — keys are already
// fully-qualified by the caller). Defaults match the Redis limiter so switching
// backends does not change limits.
func NewMemoryRateLimiter(cfg clients.RateLimiterConfig) *MemoryRateLimiter {
	if cfg.Limit <= 0 {
		cfg.Limit = 100 // sensible default (matches RedisRateLimiter)
	}
	if cfg.Window < time.Second {
		cfg.Window = time.Minute // minimum 1 second, default 1 minute
	}
	return &MemoryRateLimiter{
		entries:    make(map[string]*memWindow),
		limit:      cfg.Limit,
		window:     cfg.Window,
		sweepEvery: cfg.Window * 2,
		nowFn:      time.Now,
	}
}

// Allow implements RateLimiter using the same sliding-window approximation as
// RedisRateLimiter, guarded by a mutex for goroutine safety. It never returns
// an error: an in-memory store cannot be "unavailable", so the fail-open path
// only applies to the Redis backend.
func (m *MemoryRateLimiter) Allow(_ context.Context, key string) (bool, time.Duration, error) {
	now := m.nowFn()
	nowMs := now.UnixMilli()
	windowMs := m.window.Milliseconds()
	currentWindowStart := (nowMs / windowMs) * windowMs
	previousWindowStart := currentWindowStart - windowMs

	m.mu.Lock()
	defer m.mu.Unlock()

	m.sweepLocked(previousWindowStart, now)

	e := m.entries[key]
	if e == nil {
		e = &memWindow{windowStart: currentWindowStart}
		m.entries[key] = e
	}

	// Roll the window forward to the current one, carrying `current` into
	// `previous` when we advance exactly one window, and clearing both when the
	// entry is older than the previous window (fully aged out).
	switch e.windowStart {
	case currentWindowStart:
		// same window — no roll needed
	case previousWindowStart:
		e.previous = e.current
		e.current = 0
		e.windowStart = currentWindowStart
	default:
		e.previous = 0
		e.current = 0
		e.windowStart = currentWindowStart
	}

	elapsed := nowMs - currentWindowStart
	overlap := 1.0 - float64(elapsed)/float64(windowMs)
	if overlap < 0 {
		overlap = 0
	}
	effective := float64(e.current) + float64(e.previous)*overlap

	if effective >= float64(m.limit) {
		retryAfter := m.retryAfter(e, elapsed, windowMs)
		return false, retryAfter, nil
	}

	e.current++
	return true, 0, nil
}

// retryAfter mirrors the Lua retry-after computation: how long until the sliding
// effective count would drop below the limit.
func (m *MemoryRateLimiter) retryAfter(e *memWindow, elapsed, windowMs int64) time.Duration {
	var retryMs int64
	if e.previous > 0 && e.current < m.limit {
		targetOverlap := (float64(m.limit) - float64(e.current) - 0.001) / float64(e.previous)
		if targetOverlap < 0 {
			targetOverlap = 0
		}
		targetElapsed := float64(windowMs) * (1 - targetOverlap)
		retryMs = int64(math.Ceil(targetElapsed - float64(elapsed)))
	} else {
		retryMs = windowMs - elapsed
	}
	if retryMs < 1 {
		retryMs = 1
	}
	return time.Duration(retryMs) * time.Millisecond
}

// sweepLocked periodically removes entries whose window has fully aged out
// (older than the previous window), keeping the map bounded to recently-active
// keys. Caller must hold m.mu.
func (m *MemoryRateLimiter) sweepLocked(previousWindowStart int64, now time.Time) {
	if now.Sub(m.lastSweep) < m.sweepEvery {
		return
	}
	m.lastSweep = now
	for k, e := range m.entries {
		if e.windowStart < previousWindowStart {
			delete(m.entries, k)
		}
	}
}
