package mgmtapi

import (
	"context"
	"net/http"

	"github.com/harbor-auth/harbor/internal/telemetry"
)

// CallerSource resolves the authenticated caller's internal user ID from a
// request context. The context is populated by the BFF session middleware
// (internal/bff.Middleware) before the request reaches any handler.
//
// mgmtapi must not import internal/bff directly because bff/dashboard.go
// already imports mgmtapi (for AuditTrailDeps), so a direct import would
// create a circular dependency. The injected interface keeps the two packages
// decoupled while preserving the correct auth seam — the BFF session, never a
// client-supplied header.
//
// The production adapter (a thin wrapper around bff.UserIDFromContext) is
// injected by cmd/harbor-mgmt. The test adapter is fakeCallerSource.
type CallerSource interface {
	// CallerID returns the authenticated user's internal ID from the context,
	// or "" when the request carries no authenticated BFF session.
	CallerID(ctx context.Context) string
}

// callerID resolves the authenticated caller for a user-scoped endpoint. It
// reads from s.callerSource (set by the BFF session middleware via the context)
// and, when the caller is absent, writes the standard 401 envelope and returns
// ok=false. Handlers should return immediately when ok is false.
//
// This is the single place where "who is the caller?" is decided for every
// user-scoped cold-path endpoint. Deleting the old r.Header.Get(UserIDHeader)
// call sites and replacing them with this helper removes the spoofable-header
// vulnerability at every call site simultaneously.
func (s *Server) callerID(w http.ResponseWriter, r *http.Request, endpoint telemetry.EndpointName) (string, bool) {
	var userID string
	if s.callerSource != nil {
		userID = s.callerSource.CallerID(r.Context())
	}
	if userID == "" {
		recordError(endpoint, "unauthorized")
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "user authentication required")
		return "", false
	}
	return userID, true
}

// WithCallerSource attaches the CallerSource used by every user-scoped
// cold-path handler to resolve the authenticated caller from the BFF session
// context. A nil source leaves every user-scoped endpoint returning 401 (no
// authenticated session). Returns s for chaining.
func (s *Server) WithCallerSource(src CallerSource) *Server {
	s.callerSource = src
	return s
}
