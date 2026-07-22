package oidcapi

import (
	"net/http"
	"time"

	"github.com/harbor/harbor/internal/telemetry"
)

// GetJwks serves GET /jwks.json — the JWKS document for offline token
// verification (RFC 7517, docs/DESIGN.md §3.3, §7.3).
//
// The document is precomputed at Server construction and cached, because the
// JWKS changes only on key rotation (which restarts the process in v1).
// Cache-Control allows edge-caching with a conservative 5-minute TTL; rotation
// must overlap (publish new kid, keep old keys until old tokens expire).
func (s *Server) GetJwks(w http.ResponseWriter, _ *http.Request) {
	start := time.Now()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.jwksBytes)
	recordRequest(telemetry.EndpointJWKS, telemetry.OutcomeSuccess, start)
}
