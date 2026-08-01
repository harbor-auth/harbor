package mgmtapi

import (
	"context"
	"net"
	"net/http"

	"github.com/harbor-auth/harbor/internal/clients"
)

// productionAbuseGate dispatches sensitive endpoint checks to independent
// shared limiters. A missing limiter or backend error denies the request.
type productionAbuseGate struct {
	limiters map[string]clients.RateLimiter
}

func (g *productionAbuseGate) Check(ctx context.Context, endpoint, key string) bool {
	if g == nil {
		return true
	}
	limiter := g.limiters[endpoint]
	if limiter == nil {
		return false
	}
	allowed, _, err := limiter.Allow(ctx, key)
	return err == nil && allowed
}

// WithProductionAbuseProtection installs a shared limiter for one sensitive
// endpoint family. Repeated calls add independent namespaces.
func (s *Server) WithProductionAbuseProtection(endpoint string, limiter clients.RateLimiter) *Server {
	if s.abuseGate == nil {
		s.abuseGate = &productionAbuseGate{limiters: make(map[string]clients.RateLimiter)}
	}
	s.abuseGate.limiters[endpoint] = limiter
	return s
}

func (s *Server) rejectAbuse(w http.ResponseWriter, r *http.Request, endpoint string) bool {
	if s.abuseGate == nil {
		return false
	}
	if s.abuseGate.Check(r.Context(), endpoint, abuseSource(r)) {
		return false
	}
	w.Header().Set("Retry-After", "1")
	s.writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
	return true
}

func abuseSource(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}
