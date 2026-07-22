package oidcapi

import (
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

// RateLimitConfig configures a single rate-limiting middleware instance. One
// instance guards one hot-path endpoint (/introspect, /token, /authorize), so
// each endpoint gets an independent bucket namespace and its own limit/window.
type RateLimitConfig struct {
	// Limiter is the backend (Redis in prod, in-memory in dev). When nil the
	// middleware is a transparent passthrough — rate limiting is simply
	// disabled, which keeps wiring safe when no limiter is configured.
	Limiter clients.RateLimiter
	// Endpoint is the allow-listed route name. It namespaces the rate-limit key
	// (so /token and /authorize never share a bucket) and labels the aggregate
	// 429 / fail-open metrics.
	Endpoint telemetry.EndpointName
	// Window is the limiter's sliding-window duration. It is used ONLY to clamp
	// the Retry-After header to [0, Window]; the enforced limit lives in the
	// Limiter itself.
	Window time.Duration
	// Logger records fail-open events. It MUST never be given the rate-limit key
	// (which contains client_id or IP) — only PII-free aggregate fields.
	Logger *slog.Logger
	// TrustedForwardedHeader is the header a trusted upstream proxy sets with the
	// real client IP (e.g. "X-Forwarded-For"). It is consulted only for the
	// anonymous (no client_id) bucket. Empty means "trust no forwarded header"
	// and fall back to the transport RemoteAddr.
	TrustedForwardedHeader string
}

// RateLimitMiddleware returns net/http middleware that rate-limits a single
// hot-path endpoint, keyed per authenticated client_id or, for anonymous
// requests, per source IP (docs/plans/rate-limiting.md).
//
// Behaviour:
//   - Authenticated requests bucket by the client_id from HTTP Basic auth
//     (RFC 6749 §2.3.1); anonymous requests bucket by source IP.
//   - Over-limit → 429 Too Many Requests with a Retry-After header (clamped to
//     [0, Window]) and the standard rate_limited error envelope.
//   - Backend error (e.g. Redis down) → FAIL OPEN: the request is allowed, a
//     warning is logged, and the rate_limiter_unavailable metric is emitted.
//     Blocking real users during a cache outage would be worse than briefly
//     degrading abuse defenses.
//
// The rate-limit key is NEVER logged or used as a metric label — it carries
// client_id or IP (PII). Only aggregate endpoint/region dimensions are emitted.
func RateLimitMiddleware(cfg RateLimitConfig) func(http.Handler) http.Handler {
	// Nil limiter → disabled: return a transparent passthrough so callers can
	// wire the middleware unconditionally.
	if cfg.Limiter == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	window := cfg.Window
	if window <= 0 {
		window = time.Minute
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identifier := rateLimitIdentifier(r, cfg.TrustedForwardedHeader)
			key := clients.RateLimitKey(string(cfg.Endpoint), identifier)

			allowed, retryAfter, err := cfg.Limiter.Allow(r.Context(), key)

			// Region is only a metric dimension here; resolve best-effort and pass
			// empty when the host is unknown (metrics accept an empty region).
			reg, _ := region.Resolve(r.Host)

			if err != nil {
				// Fail open: allow the request. Log with PII-free aggregate fields
				// only — never the key (client_id / IP).
				logger.Warn("rate limiter unavailable, failing open",
					slog.String("event", "rate_limiter_unavailable"),
					slog.String("endpoint", string(cfg.Endpoint)),
					slog.String("component", "oidcapi"),
				)
				recordRateLimiterUnavailable(cfg.Endpoint, reg)
				next.ServeHTTP(w, r)
				return
			}

			if !allowed {
				writeRateLimited(w, cfg.Endpoint, reg, retryAfter, window)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// rateLimitIdentifier derives the bucket identifier for a request: the
// authenticated client_id when present (HTTP Basic auth username, RFC 6749
// §2.3.1), otherwise the source IP. Both are acceptable rate-limit keys and
// neither creates per-user tracking (client_id is RP-scoped; IP is not tied to
// a Harbor user identity).
func rateLimitIdentifier(r *http.Request, trustedHeader string) string {
	if clientID, _, ok := r.BasicAuth(); ok && clientID != "" {
		return clientID
	}
	return clientIP(r, trustedHeader)
}

// clientIP extracts the source IP, preferring the leftmost address in the
// trusted forwarded header (the original client) when one is configured and
// present, and falling back to the transport RemoteAddr. When RemoteAddr has no
// port it is returned as-is.
func clientIP(r *http.Request, trustedHeader string) string {
	if trustedHeader != "" {
		if v := r.Header.Get(trustedHeader); v != "" {
			// "X-Forwarded-For: client, proxy1, proxy2" — the leftmost entry is
			// the original client.
			if first := strings.TrimSpace(strings.Split(v, ",")[0]); first != "" {
				return first
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// writeRateLimited records the aggregate 429 metric, sets a clamped Retry-After
// header, and writes the rate_limited error envelope. Retry-After MUST be set
// before writeError writes the status line (headers are frozen after WriteHeader).
func writeRateLimited(w http.ResponseWriter, endpoint telemetry.EndpointName, reg region.Region, retryAfter, window time.Duration) {
	recordRateLimited(endpoint, reg)
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(retryAfter, window)))
	writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
}

// retryAfterSeconds clamps retryAfter to [0, window] and rounds up to whole
// delta-seconds (RFC 7231 §7.1.3). Rounding up avoids advising a client to
// retry a moment before its bucket actually refills.
func retryAfterSeconds(retryAfter, window time.Duration) int {
	if retryAfter < 0 {
		retryAfter = 0
	}
	if retryAfter > window {
		retryAfter = window
	}
	secs := int(math.Ceil(retryAfter.Seconds()))
	if secs < 0 {
		secs = 0
	}
	return secs
}
