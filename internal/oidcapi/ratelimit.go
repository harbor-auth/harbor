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
	// anonymous (no client_id) bucket when TrustedProxyHops > 0.
	TrustedForwardedHeader string
	// TrustedProxyHops is the number of trusted reverse-proxy hops between the
	// internet and Harbor. When 0 (the default), the forwarded header is ignored
	// entirely and RemoteAddr is used — safe for direct exposure. When N > 0,
	// the Nth-from-right entry in TrustedForwardedHeader is used: each trusted
	// proxy appends its observed client IP on the right, so only the rightmost
	// entries are unforgeable.
	//
	// With nginx-ingress's default $proxy_add_x_forwarded_for, the client can
	// inject arbitrary leftmost entries, making TRUSTED_PROXY_HOPS=0 the safe
	// default. Set TRUSTED_PROXY_HOPS=1 for a single nginx-ingress, =2 if an
	// additional L7 load balancer also appends. Over-counting hops reads into
	// the attacker-controlled region (bypass); under-counting buckets on a proxy
	// IP (over-limit). Count only proxies you control that append to the header.
	TrustedProxyHops int
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
			identifier := rateLimitIdentifier(r, cfg.TrustedForwardedHeader, cfg.TrustedProxyHops)
			key := clients.RateLimitKey(string(cfg.Endpoint), identifier)

			allowed, retryAfter, err := cfg.Limiter.Allow(r.Context(), key)

			// Region is only a metric dimension here; resolve best-effort and pass
			// empty when the host is unknown (metrics accept an empty region).
			reg, _ := region.Resolve(r.Host) //nolint:errcheck // best-effort metric dimension; empty region is accepted

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
func rateLimitIdentifier(r *http.Request, trustedHeader string, trustedHops int) string {
	if clientID, _, ok := r.BasicAuth(); ok && clientID != "" {
		return clientID
	}
	return clientIP(r, trustedHeader, trustedHops)
}

// clientIP extracts the source IP using the trusted-proxy-hop model.
//
// When trustedHops is 0 (the default), the forwarded header is ignored and
// RemoteAddr is always used — safe when Harbor is directly exposed.
//
// When trustedHops is N > 0, it takes the Nth-from-right entry in trustedHeader.
// nginx-ingress's default $proxy_add_x_forwarded_for APPENDS the observed
// client IP to the right of any client-supplied header values, so only the
// rightmost entries are unforgeable. TRUSTED_PROXY_HOPS=1 recovers the real
// client IP behind a single nginx-ingress; =2 for an additional L7 LB that
// also appends. If the header is shorter than hops (attacker stripped it),
// we fall back to RemoteAddr — never to the leftmost/forgeable entry.
func clientIP(r *http.Request, trustedHeader string, trustedHops int) string {
	if trustedHops > 0 && trustedHeader != "" {
		if v := r.Header.Get(trustedHeader); v != "" {
			parts := strings.Split(v, ",")
			// Take the Nth-from-right entry (1-indexed): hops=1 → rightmost.
			idx := len(parts) - trustedHops
			if idx >= 0 {
				if ip := strings.TrimSpace(parts[idx]); ip != "" {
					return ip
				}
			}
			// Header shorter than hops or empty entry — fall through to RemoteAddr.
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
