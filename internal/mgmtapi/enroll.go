package mgmtapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

// parseUUIDToBytes converts a UUID string to its 16-byte binary representation
// for use as a WebAuthn user handle.
func parseUUIDToBytes(s string) ([]byte, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return nil, err
	}
	return id[:], nil
}

// maxEnrollBody caps the enrollment request body. The body carries only a
// region string, so a few KB is far beyond any legitimate request and stops a
// flooded /enroll from exhausting memory (docs/DESIGN.md §6.5).
const maxEnrollBody = 4 * 1024

// statusPending is the enrollment lifecycle status returned to the caller. It
// is distinct from the users.status DB column (which is "active" on insert):
// the account is not usable until passkey registration completes (§11.1), so
// the enrollment API reports "pending" until that second step lands.
const statusPending = "pending"

// enrollRequest is the POST /enroll JSON body.
type enrollRequest struct {
	Region string `json:"region"`
}

// enrollResponse is the POST /enroll success body: the new user's ID plus the
// pending lifecycle status.
type enrollResponse struct {
	UserID string `json:"user_id"`
	Region string `json:"region"`
	Status string `json:"status"`
}

// PostEnroll is the enrollment front door (POST /enroll, docs/DESIGN.md §11.1).
// It validates the requested region, creates a new sealed user via the
// Enroller, and returns the new user ID with status=pending. The user stays
// pending until passkey registration completes.
//
// Responses:
//   - 201 Created             on success ({user_id, region, status:"pending"})
//   - 400 Bad Request         malformed body or unknown region
//   - 503 Service Unavailable enrollment not wired (no DB / KEK)
//   - 500 Internal Server Error any other enrollment failure
func (s *Server) PostEnroll(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointEnroll, outcome, start) }()

	if s.enroller == nil {
		recordError(telemetry.EndpointEnroll, "unavailable")
		s.writeError(w, http.StatusServiceUnavailable, "unavailable",
			"enrollment is not configured on this instance")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxEnrollBody)
	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		recordError(telemetry.EndpointEnroll, "invalid_request")
		s.writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON request body")
		return
	}

	// Validate the region up front so a bad region is a clean 400 and cannot be
	// confused with a server-side enrollment failure below. req.Region is a
	// region *code* (e.g. "us", "eu"), not a host, so region.Parse is the correct
	// validator here — region.Resolve maps hosts (e.g. "us.harbor.id") and would
	// reject every valid enrollment. Parse is pure and deterministic, so this
	// does not race with Enroll's own parse.
	if _, err := region.Parse(req.Region); err != nil {
		recordError(telemetry.EndpointEnroll, "invalid_region")
		s.writeError(w, http.StatusBadRequest, "invalid_region", "unknown or unsupported region")
		return
	}

	res, err := s.enroller.Enroll(r.Context(), req.Region)
	if err != nil {
		// Region is already validated, so a failure here is server-side (DEK
		// generation, KEK wrap, encrypt, or DB persist). The error may carry
		// internal detail, so log it and return a generic 500 (docs/DESIGN.md §6.5).
		s.logger.ErrorContext(r.Context(), "enrollment failed", "error", err)
		recordError(telemetry.EndpointEnroll, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "enrollment failed")
		return
	}

	// When an enrollment session store is wired, save the new user's handle and
	// set an HttpOnly cookie so the passkey registration ceremony can bind to
	// this user WITHOUT a client-supplied user_id (docs/DESIGN.md §9, §11.1).
	if s.sessions != nil {
		key, err := NewEnrollmentSessionKey()
		if err != nil {
			s.logger.ErrorContext(r.Context(), "generate enrollment session key failed", "error", err)
			recordError(telemetry.EndpointEnroll, "server_error")
			s.writeError(w, http.StatusInternalServerError, "server_error", "enrollment failed")
			return
		}
		// The user handle for WebAuthn is the raw UUID bytes. Parse the UUID string
		// returned by Enroll and use its byte representation.
		userHandle, err := parseUUIDToBytes(res.UserID)
		if err != nil {
			s.logger.ErrorContext(r.Context(), "parse user ID failed", "error", err)
			recordError(telemetry.EndpointEnroll, "server_error")
			s.writeError(w, http.StatusInternalServerError, "server_error", "enrollment failed")
			return
		}
		if err := s.sessions.Save(r.Context(), key, userHandle); err != nil {
			s.logger.ErrorContext(r.Context(), "save enrollment session failed", "error", err)
			recordError(telemetry.EndpointEnroll, "server_error")
			s.writeError(w, http.StatusInternalServerError, "server_error", "enrollment failed")
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     EnrollmentSessionCookieName,
			Value:    key,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   600, // 10 min — matches the session store TTL.
		})
	}

	outcome = telemetry.OutcomeSuccess
	s.writeJSON(w, http.StatusCreated, enrollResponse{
		UserID: res.UserID,
		Region: res.Region,
		Status: statusPending,
	})
}
