package oidcapi

import "net/http"

// GetHealthz serves the liveness probe: GET /healthz -> 200 "ok".
// (openapi.ServerInterface / api/openapi/harbor.yaml operationId getHealthz.)
func (s *Server) GetHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
