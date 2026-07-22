package oidcapi

import (
	"encoding/json"
	"net/http"

	"github.com/harbor/harbor/internal/gen/openapi"
)

// PostIntrospect implements the RFC 7662 Token Introspection endpoint.
//
// Callers must authenticate via Basic auth (client_id:client_secret) or an
// admin Bearer token. Anonymous callers receive 401. Cross-client isolation is
// enforced: a client may only introspect tokens whose `aud` matches its own
// `client_id`; cross-client queries return `{"active":false}` (no information
// leakage). All negative responses (expired, revoked, invalid, cross-client)
// return 200 with `{"active":false}` for enumeration resistance (DESIGN §3.3,
// §3.5).
//
// TODO(introspect): wire full implementation — caller auth, JWT verify,
// revocation check, cross-client isolation.
func (s *Server) PostIntrospect(w http.ResponseWriter, r *http.Request) {
	// Stub: return inactive for all tokens until full implementation lands.
	// This satisfies the ServerInterface contract and allows the codebase to
	// compile while the handler logic is built out in subsequent tasks.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(openapi.IntrospectResponse{Active: false})
}
