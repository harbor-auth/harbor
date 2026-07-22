package mgmtapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/harbor/harbor/internal/identity"
	"github.com/harbor/harbor/internal/region"
	"github.com/harbor/harbor/internal/telemetry"
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
	// clientReg, when non-nil, persists dynamically-registered clients for the
	// RFC 7591 POST /register endpoint. Nil puts /register into a 503 state.
	clientReg ClientRegistrationStore
	// clientMgmt, when non-nil, backs the RFC 7592 client configuration
	// endpoints (GET/PUT/DELETE /register/{client_id}). It is wired from the same
	// store as clientReg when that store also satisfies ClientManagementStore
	// (clients.DBClientRegistrationStore does). Nil puts those routes in a 503
	// state.
	clientMgmt ClientManagementStore
	// registrationBaseURL is the external base URL used to build each client's
	// RFC 7592 registration_client_uri ({base}/register/{client_id}).
	registrationBaseURL string
	// initialAccessTokenHash, when non-nil, gates POST /register: callers must
	// present the matching initial access token as a Bearer credential, or the
	// endpoint returns 401 and persists nothing (RFC 7591 §1.2, §3). Nil disables
	// the gate (open registration). The token is stored HASHED, never plaintext.
	initialAccessTokenHash []byte
	// consents provides access to consent grants for the authenticated user.
	// May be nil in dev-scaffold mode; GetConsentGrants then returns 503.
	consents ConsentStore
	// sessionRevoker cascades consent revocation to active sessions with the RP.
	// May be nil (dev-scaffold mode); DeleteConsentGrant then skips the cascade.
	sessionRevoker SessionRevoker
	logger         *slog.Logger
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

// WithClientRegistration wires the RFC 7591 POST /register endpoint. store
// persists new clients; baseURL is the external base used to build each
// client's registration_client_uri ({baseURL}/register/{client_id}). A nil
// store leaves /register in a 503 state. Returns s for chaining.
func (s *Server) WithClientRegistration(store ClientRegistrationStore, baseURL string) *Server {
	s.clientReg = store
	s.registrationBaseURL = baseURL
	// A store that also implements the RFC 7592 management behaviour (the
	// production *clients.DBClientRegistrationStore does) transparently enables
	// the GET/PUT/DELETE /register/{client_id} routes.
	if mgmt, ok := store.(ClientManagementStore); ok {
		s.clientMgmt = mgmt
	}
	return s
}

// WithInitialAccessToken gates the RFC 7591 POST /register endpoint behind an
// initial access token (RFC 7591 §1.2, §3). When token is non-empty, callers
// must present it as a Bearer credential in the Authorization header or the
// endpoint returns 401 and persists nothing. An empty token leaves the gate
// open (anonymous registration). The token is stored HASHED and compared in
// constant time, so a configured value never lingers in plaintext. Returns s
// for chaining.
func (s *Server) WithInitialAccessToken(token string) *Server {
	if token != "" {
		s.initialAccessTokenHash = HashSecret(token)
	}
	return s
}

// WithConsentStore attaches the consent store for consent grant management.
// When set, GET /consent-grants returns the user's active grants. A nil store
// returns 503 Service Unavailable. Returns s for chaining.
func (s *Server) WithConsentStore(consents ConsentStore) *Server {
	s.consents = consents
	return s
}

// WithSessionRevoker attaches the session revoker used to cascade consent
// revocation to active refresh-token sessions. When set, DELETE
// /consent-grants/{client_id} also revokes the user's sessions with that RP.
// A nil revoker skips the cascade. Returns s for chaining.
func (s *Server) WithSessionRevoker(revoker SessionRevoker) *Server {
	s.sessionRevoker = revoker
	return s
}

// Routes registers harbor-mgmt's cold-path routes on mux. It is additive: the
// caller owns the mux (typically httpserver.NewHealthMux) and its /healthz route.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /enroll", s.PostEnroll)
	mux.HandleFunc("POST /register", s.PostRegister)
	mux.HandleFunc("GET /register/{client_id}", s.GetRegister)
	mux.HandleFunc("PUT /register/{client_id}", s.PutRegister)
	mux.HandleFunc("DELETE /register/{client_id}", s.DeleteRegister)
	mux.HandleFunc("GET /consent-grants", s.GetConsentGrants)
	mux.HandleFunc("DELETE /consent-grants/{client_id}", s.DeleteConsentGrant)
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

// WriteRateLimited writes a 429 Too Many Requests response and records the
// rejection as an AGGREGATE metric by endpoint and region. It is the single
// call site a rate-limiter (or edge middleware) uses so every 429 is metered
// consistently. Crucially it NEVER records a per-IP series — abuse visibility
// without PII (docs/plans/observability-metrics.md, docs/DESIGN.md §6.5). Pass
// an empty region.Region when the request region is not yet resolved.
func (s *Server) WriteRateLimited(w http.ResponseWriter, endpoint telemetry.EndpointName, reg region.Region) {
	recordRateLimited(endpoint, reg)
	s.writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
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
