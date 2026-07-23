package mgmtapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/harbor-auth/harbor/internal/mfa"
)

// maxMFABody caps MFA request bodies. They carry only a short TOTP or recovery
// code, so a few KB is far beyond any legitimate request and stops a flooded
// endpoint from exhausting memory (docs/DESIGN.md §6.5).
const maxMFABody = 4 * 1024

// MFAService is the narrow behaviour the MFA handlers need from the TOTP core.
// Depending on the interface (not the concrete *mfa.Service) keeps the HTTP
// layer unit-testable with a fake and free of crypto/DB wiring. It is satisfied
// by *mfa.Service (mfa.TOTPService).
type MFAService interface {
	Enroll(ctx context.Context, userID string) (*mfa.EnrollResult, error)
	Activate(ctx context.Context, userID, code string) error
	Verify(ctx context.Context, userID, code string) error
	VerifyRecoveryCode(ctx context.Context, userID, code string) error
	ListFactors(ctx context.Context, userID string) ([]mfa.Factor, error)
	Disable(ctx context.Context, userID string) error
}

// Compile-time assertion: the production *mfa.Service satisfies MFAService, so
// the wiring in cmd/harbor-mgmt can never silently drift from the handler's
// expectations.
var _ MFAService = (*mfa.Service)(nil)

// mfaCodeRequest is the JSON body for the code-carrying MFA endpoints (activate,
// verify, verify-recovery).
type mfaCodeRequest struct {
	Code string `json:"code"`
}

// mfaEnrollResponse is the POST /mfa/enroll success body. It carries the only
// plaintext material the user will ever see: the base32 secret (for manual
// entry), the otpauth:// provisioning URI (rendered as a QR code), and the
// single-use recovery codes. None of it is persisted in the clear.
type mfaEnrollResponse struct {
	FactorID        string   `json:"factor_id"`
	Secret          string   `json:"secret"`
	ProvisioningURI string   `json:"provisioning_uri"`
	RecoveryCodes   []string `json:"recovery_codes"`
}

// mfaFactor is the PII-free metadata view of a single enrolled factor.
type mfaFactor struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Used      bool   `json:"used"`
	CreatedAt string `json:"created_at"`
}

// mfaFactorsResponse is the GET /mfa/factors success body.
type mfaFactorsResponse struct {
	Factors []mfaFactor `json:"factors"`
	Count   int         `json:"count"`
}

// mfaStatusResponse is the generic success body for the verify/activate
// endpoints, reporting the outcome without echoing any secret.
type mfaStatusResponse struct {
	Status string `json:"status"`
}

// mfaUserID resolves the authenticated user id from the upstream-set header,
// writing a 401 and returning ok=false when absent. Every MFA endpoint is for
// an already-authenticated user managing their own factors.
func (s *Server) mfaUserID(w http.ResponseWriter, r *http.Request) (string, bool) {
	userID := r.Header.Get(UserIDHeader)
	if userID == "" {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "user authentication required")
		return "", false
	}
	return userID, true
}

// decodeMFACode reads and validates a code-carrying MFA request body, writing a
// 400 and returning ok=false on a malformed or empty payload.
func (s *Server) decodeMFACode(w http.ResponseWriter, r *http.Request) (string, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxMFABody)
	var req mfaCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON request body")
		return "", false
	}
	if req.Code == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return "", false
	}
	return req.Code, true
}

// PostMFAEnroll handles POST /mfa/enroll — it begins TOTP enrollment for the
// authenticated user, returning the shared secret, provisioning URI, and
// single-use recovery codes exactly once. The new factor is PENDING until
// confirmed via POST /mfa/activate.
//
// Responses:
//   - 201 Created             on success ({factor_id, secret, provisioning_uri, recovery_codes})
//   - 401 Unauthorized        missing authenticated user
//   - 409 Conflict            user already has an active TOTP factor
//   - 503 Service Unavailable MFA not wired
//   - 500 Internal Server Error enrollment failure
func (s *Server) PostMFAEnroll(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.mfaUserID(w, r)
	if !ok {
		return
	}
	if s.mfa == nil {
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "MFA is not configured on this instance")
		return
	}

	res, err := s.mfa.Enroll(r.Context(), userID)
	if err != nil {
		if errors.Is(err, mfa.ErrAlreadyEnrolled) {
			s.writeError(w, http.StatusConflict, "already_enrolled", "an active TOTP factor is already enrolled")
			return
		}
		s.logger.ErrorContext(r.Context(), "mgmtapi: MFA enroll failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to begin MFA enrollment")
		return
	}

	s.writeJSON(w, http.StatusCreated, mfaEnrollResponse{
		FactorID:        res.FactorID,
		Secret:          res.Secret,
		ProvisioningURI: res.ProvisioningURI,
		RecoveryCodes:   res.RecoveryCodes,
	})
}

// PostMFAActivate handles POST /mfa/activate — it confirms a pending TOTP
// enrollment by verifying the user can produce a valid code, promoting the
// factor to active.
//
// Responses:
//   - 200 OK                  on success ({status:"activated"})
//   - 400 Bad Request         malformed body, or no pending enrollment
//   - 401 Unauthorized        missing authenticated user, or invalid code
//   - 503 Service Unavailable MFA not wired
//   - 500 Internal Server Error activation failure
func (s *Server) PostMFAActivate(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.mfaUserID(w, r)
	if !ok {
		return
	}
	if s.mfa == nil {
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "MFA is not configured on this instance")
		return
	}
	code, ok := s.decodeMFACode(w, r)
	if !ok {
		return
	}

	if err := s.mfa.Activate(r.Context(), userID, code); err != nil {
		s.writeMFAVerifyError(w, r, err, "failed to activate MFA")
		return
	}
	s.writeJSON(w, http.StatusOK, mfaStatusResponse{Status: "activated"})
}

// PostMFAVerify handles POST /mfa/verify — it validates a TOTP code against the
// user's active factor for a step-up challenge.
//
// Responses:
//   - 200 OK                  on success ({status:"verified"})
//   - 400 Bad Request         malformed body, or no active factor
//   - 401 Unauthorized        missing authenticated user, or invalid code
//   - 503 Service Unavailable MFA not wired
//   - 500 Internal Server Error verification failure
func (s *Server) PostMFAVerify(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.mfaUserID(w, r)
	if !ok {
		return
	}
	if s.mfa == nil {
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "MFA is not configured on this instance")
		return
	}
	code, ok := s.decodeMFACode(w, r)
	if !ok {
		return
	}

	if err := s.mfa.Verify(r.Context(), userID, code); err != nil {
		s.writeMFAVerifyError(w, r, err, "failed to verify MFA code")
		return
	}
	s.writeJSON(w, http.StatusOK, mfaStatusResponse{Status: "verified"})
}

// PostMFAVerifyRecovery handles POST /mfa/verify-recovery — it validates a
// single-use recovery code and burns it on success.
//
// Responses:
//   - 200 OK                  on success ({status:"verified"})
//   - 400 Bad Request         malformed body
//   - 401 Unauthorized        missing authenticated user, or invalid code
//   - 503 Service Unavailable MFA not wired
//   - 500 Internal Server Error verification failure
func (s *Server) PostMFAVerifyRecovery(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.mfaUserID(w, r)
	if !ok {
		return
	}
	if s.mfa == nil {
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "MFA is not configured on this instance")
		return
	}
	code, ok := s.decodeMFACode(w, r)
	if !ok {
		return
	}

	if err := s.mfa.VerifyRecoveryCode(r.Context(), userID, code); err != nil {
		s.writeMFAVerifyError(w, r, err, "failed to verify recovery code")
		return
	}
	s.writeJSON(w, http.StatusOK, mfaStatusResponse{Status: "verified"})
}

// GetMFAFactors handles GET /mfa/factors — it lists the authenticated user's
// enrolled MFA factors as PII-free metadata (never secrets or hashes).
//
// Responses:
//   - 200 OK                  on success ({factors, count})
//   - 401 Unauthorized        missing authenticated user
//   - 503 Service Unavailable MFA not wired
//   - 500 Internal Server Error listing failure
func (s *Server) GetMFAFactors(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.mfaUserID(w, r)
	if !ok {
		return
	}
	if s.mfa == nil {
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "MFA is not configured on this instance")
		return
	}

	factors, err := s.mfa.ListFactors(r.Context(), userID)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: MFA factor listing failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to list MFA factors")
		return
	}

	out := make([]mfaFactor, 0, len(factors))
	for _, f := range factors {
		out = append(out, mfaFactor{
			ID:        f.ID,
			Type:      string(f.Type),
			Used:      f.Used,
			CreatedAt: f.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	s.writeJSON(w, http.StatusOK, mfaFactorsResponse{Factors: out, Count: len(out)})
}

// DeleteMFAFactor handles DELETE /mfa/factors/{id} — it disables MFA for the
// authenticated user. Harbor allows a single active TOTP factor per user, so
// removing it also clears the associated recovery codes: the user is returned
// to an MFA-disabled state and the step-up gate stops challenging them. The
// {id} path segment identifies the factor the client is acting on; deletion is
// always scoped to the authenticated user's own factors.
//
// Responses:
//   - 204 No Content          on success
//   - 400 Bad Request         missing factor id
//   - 401 Unauthorized        missing authenticated user
//   - 503 Service Unavailable MFA not wired
//   - 500 Internal Server Error deletion failure
func (s *Server) DeleteMFAFactor(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.mfaUserID(w, r)
	if !ok {
		return
	}
	if s.mfa == nil {
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "MFA is not configured on this instance")
		return
	}
	if r.PathValue("id") == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "factor id is required")
		return
	}

	if err := s.mfa.Disable(r.Context(), userID); err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: MFA disable failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to disable MFA")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeMFAVerifyError maps a code-verification error to an HTTP response. A
// mismatched code is a uniform 401 and an absent factor a 400; any other error
// is an internal fault (logged, generic 500). Keeping invalid-code responses
// uniform ensures the reply never discloses more than "that code did not work".
func (s *Server) writeMFAVerifyError(w http.ResponseWriter, r *http.Request, err error, serverMsg string) {
	switch {
	case errors.Is(err, mfa.ErrInvalidCode):
		s.writeError(w, http.StatusUnauthorized, "invalid_code", "invalid code")
	case errors.Is(err, mfa.ErrNotEnrolled):
		s.writeError(w, http.StatusBadRequest, "not_enrolled", "no MFA factor is enrolled")
	default:
		s.logger.ErrorContext(r.Context(), "mgmtapi: MFA verification failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", serverMsg)
	}
}
