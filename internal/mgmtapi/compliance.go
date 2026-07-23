package mgmtapi

import (
	"context"
	"net/http"
	"time"

	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

// BundleAssembler assembles the authenticated caller's DSAR export bundle.
// Satisfied by *identity.ExportBundler. The returned bundle is decrypted only
// under the caller's own DEK — no cross-user reads, no operator plaintext path.
type BundleAssembler interface {
	Assemble(ctx context.Context, userID string) (*identity.Bundle, error)
}

// AccountEraser performs the irreversible crypto-shred erasure lifecycle for a
// user. Satisfied by *identity.Eraser. After Erase returns nil the user's
// dek_wrapped is empty and all envelope-encrypted PII is permanently
// unrecoverable.
type AccountEraser interface {
	Erase(ctx context.Context, userID string) error
}

// ComplianceUserLoader loads the user's region (and wrapped DEK) ahead of the
// erasure step so the region is available for telemetry metering even after the
// DEK has been destroyed. Satisfied by an adapter over *db.Queries; the same
// adapter that satisfies AuditUserReader will also satisfy this interface.
type ComplianceUserLoader interface {
	LoadUserForAudit(ctx context.Context, userID string) (region string, dekWrapped []byte, err error)
}

// ComplianceDeps bundles the dependencies for POST /compliance/export and
// POST /compliance/erase. A nil ComplianceDeps (or nil individual fields) puts
// the endpoints into a 503 Service Unavailable state rather than panicking,
// consistent with the dev-scaffold pattern used across other Server deps.
type ComplianceDeps struct {
	// Bundler assembles the caller-scoped DSAR export bundle.
	Bundler BundleAssembler
	// Eraser performs the irreversible crypto-shred erasure lifecycle.
	Eraser AccountEraser
	// Users loads the user's region for telemetry metering. Required for
	// PostErase so the region is captured before the DEK is destroyed.
	Users ComplianceUserLoader
}

// PostExport handles POST /compliance/export — assembles the authenticated
// user's decrypted DSAR export bundle and returns it as JSON.
//
// The bundle is assembled strictly under the caller's own DEK (no cross-user
// reads; no operator plaintext path). It is PII and must be treated as such by
// the caller — region-pinned, short-lived, never cached cross-region.
//
// Responses:
//   - 200 OK                   on success (JSON bundle)
//   - 401 Unauthorized         missing X-Harbor-User-ID
//   - 503 Service Unavailable  compliance service not configured
//   - 500 Internal Server Error assembly or crypto failure
func (s *Server) PostExport(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointCompliance, outcome, start) }()

	userID := r.Header.Get(UserIDHeader)
	if userID == "" {
		recordError(telemetry.EndpointCompliance, "unauthorized")
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "user authentication required")
		return
	}

	if s.compliance == nil || s.compliance.Bundler == nil {
		recordError(telemetry.EndpointCompliance, "service_unavailable")
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "compliance service not configured")
		return
	}

	bundle, err := s.compliance.Bundler.Assemble(r.Context(), userID)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: compliance: export assembly failed", "error", err)
		recordError(telemetry.EndpointCompliance, "server_error")
		RecordDataRightsOp(region.Region(""), false)
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to assemble export bundle")
		return
	}

	RecordDataRightsOp(region.Region(bundle.Region), true)
	outcome = telemetry.OutcomeSuccess
	s.writeJSON(w, http.StatusOK, bundle)
}

// PostErase handles POST /compliance/erase — irreversibly crypto-shreds the
// authenticated user's account by destroying their wrapped DEK, making all
// envelope-encrypted PII permanently unrecoverable.
//
// The operation is audited (compliance.erase_requested before the shred;
// compliance.erase_completed after) and fail-closed at every step. It is
// irreversible: once dek_wrapped is overwritten there is no recovery path.
//
// Responses:
//   - 204 No Content           on success (erasure complete)
//   - 401 Unauthorized         missing X-Harbor-User-ID
//   - 503 Service Unavailable  compliance service not configured
//   - 500 Internal Server Error erasure or audit failure
func (s *Server) PostErase(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointCompliance, outcome, start) }()

	userID := r.Header.Get(UserIDHeader)
	if userID == "" {
		recordError(telemetry.EndpointCompliance, "unauthorized")
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "user authentication required")
		return
	}

	if s.compliance == nil || s.compliance.Eraser == nil {
		recordError(telemetry.EndpointCompliance, "service_unavailable")
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "compliance service not configured")
		return
	}

	// Load the user's region BEFORE the crypto-shred so it is available for
	// telemetry metering even after dek_wrapped has been destroyed. Region is
	// stored in plaintext on the user row and survives erasure.
	var userRegion region.Region
	if s.compliance.Users != nil {
		reg, _, err := s.compliance.Users.LoadUserForAudit(r.Context(), userID)
		if err != nil {
			s.logger.ErrorContext(r.Context(), "mgmtapi: compliance: erase user load failed", "error", err)
			recordError(telemetry.EndpointCompliance, "server_error")
			s.writeError(w, http.StatusInternalServerError, "server_error", "failed to process erasure request")
			return
		}
		userRegion = region.Region(reg)
	}

	if err := s.compliance.Eraser.Erase(r.Context(), userID); err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: compliance: erase failed", "error", err)
		recordError(telemetry.EndpointCompliance, "server_error")
		RecordDataRightsOp(userRegion, false)
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to process erasure request")
		return
	}

	RecordDataRightsOp(userRegion, true)
	outcome = telemetry.OutcomeSuccess
	w.WriteHeader(http.StatusNoContent)
}
