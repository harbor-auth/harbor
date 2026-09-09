package oidcapi

import (
	"encoding/json"
	"github.com/harbor-auth/harbor/internal/oidc"
	"net/http"
	"time"

	"github.com/harbor-auth/harbor/internal/telemetry"
)

// GetJwks serves GET /jwks.json — the JWKS document for offline token
// verification (RFC 7517, docs/DESIGN.md §3.3, §7.3).
//
// Production reads the current durable key set on each request.
// Cache-Control allows edge-caching with a conservative 5-minute TTL; rotation
// must overlap (publish new kid, keep old keys until old tokens expire).
func (s *Server) GetJwks(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	body := s.jwksBytes
	if s.keys != nil {
		snapshot, err := s.keys.Snapshot(r.Context())
		if err != nil {
			w.Header().Set("Cache-Control", "no-store")
			writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "signing keys unavailable")
			return
		}
		body, err = json.Marshal(oidc.BuildJWKS(snapshot.AllSigners()))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", "signing keys unavailable")
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
	recordRequest(telemetry.EndpointJWKS, telemetry.OutcomeSuccess, start)
}
