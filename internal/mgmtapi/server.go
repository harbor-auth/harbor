package mgmtapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/harbor/harbor/internal/identity"
)

// Enroller is the narrow behaviour the enrollment handler needs from
// identity.Enroller. Depending on the interface (not the concrete type) keeps
// the HTTP layer unit-testable with a fake and free of crypto/DB wiring.
type Enroller interface {
	Enroll(ctx context.Context, rawRegion string) (identity.EnrollResult, error)
}

// Server holds the dependencies for harbor-mgmt's cold-path HTTP surface
// (docs/DESIGN.md §4.2, §11.1). Today that is the enrollment front door;
// consent/audit/admin routes are layered on here in later work.
type Server struct {
	// enroller performs user enrollment. It may be nil in the dev-scaffold mode
	// (no DATABASE_URL / HARBOR_KEK_SECRET); PostEnroll then returns 503 rather
	// than panicking, so the binary still serves liveness.
	enroller Enroller
	// sessions, when non-nil, stores the enrollment→passkey handoff: after a
	// successful POST /enroll the new user's handle is saved under a fresh key
	// and returned as an HttpOnly cookie for the registration ceremony to read
	// (docs/DESIGN.md §9, §11.1). Nil leaves the cookie unset (dev-scaffold mode).
	sessions EnrollmentSessionStore
	logger   *slog.Logger
}

// New returns a Server. A nil enroller is valid and puts the enrollment route
// into an unavailable (503) state — see the Server.enroller field. A nil logger
// falls back to slog.Default().
func New(enroller Enroller, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{enroller: enroller, logger: logger}
}

// WithEnrollmentSessions attaches the enrollment session store used to bridge
// POST /enroll and the passkey registration ceremony. When set, a successful
// enrollment returns an HttpOnly cookie carrying the session key. A nil store
// leaves the cookie unset. Returns s for chaining.
func (s *Server) WithEnrollmentSessions(sessions EnrollmentSessionStore) *Server {
	s.sessions = sessions
	return s
}

// Routes registers harbor-mgmt's cold-path routes on mux. It is additive: the
// caller owns the mux (typically httpserver.NewHealthMux) and its /healthz route.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /enroll", s.PostEnroll)
}

// errorResponse is the JSON error envelope for the cold-path API. Messages are
// generic and PII-free (docs/DESIGN.md §6.5): they never disclose whether an
// account exists.
type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// writeError renders a JSON error envelope at the given status.
func (s *Server) writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(errorResponse{Error: code, Message: message}); err != nil {
		s.logger.Warn("mgmtapi: failed to encode error response", "error", err)
	}
}

// writeJSON renders v as JSON at the given status.
func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// WriteHeader already sent — status cannot change. Almost always a client
		// disconnect, so Warn (not Error).
		s.logger.Warn("mgmtapi: failed to encode response", "error", err)
	}
}
