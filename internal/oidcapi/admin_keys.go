package oidcapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/gen/openapi"
)

// maxRotateBodyBytes caps the optional JSON body of a rotate request. The body
// carries at most a single boolean flag, so a small cap is ample and prevents a
// flooded admin endpoint from exhausting memory (docs/DESIGN.md §6.5).
const maxRotateBodyBytes = 4 * 1024

// PostAdminKeysRotate handles POST /admin/keys/rotate (signing key rotation;
// docs/DESIGN.md §7.3, §3.5.4). It initiates rotation to a new signing key and
// returns the resulting schedule as JSON. Emergency rotation (zero grace period
// and overlap window) is selected via the `emergency` flag, which may be passed
// either as the `?emergency=true` query parameter or in the optional JSON body;
// the query parameter takes precedence.
//
// Admin authentication is enforced by middleware wired in front of this handler
// (the OpenAPI contract documents the 401 response); this handler assumes the
// caller is already authorized.
func (s *Server) PostAdminKeysRotate(w http.ResponseWriter, r *http.Request) {
	if s.rotator == nil {
		writeError(w, http.StatusNotImplemented, "not_implemented", "signing key rotation is not configured")
		return
	}

	emergency, ok := parseEmergency(w, r)
	if !ok {
		return // parseEmergency already wrote the error response.
	}

	result, err := s.rotator.Rotate(r.Context(), crypto.RotateOptions{Emergency: emergency})
	if err != nil {
		slog.Default().Error("oidcapi: signing key rotation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "rotation_failed", "signing key rotation failed")
		return
	}

	writeKeyRotateResponse(w, result)
}

// parseEmergency resolves the emergency flag from the request. A query parameter
// `emergency=true` takes precedence; otherwise the optional JSON body's
// `emergency` field is used. Returns (value, true) on success, or (false, false)
// after writing a 400 error for a malformed body.
func parseEmergency(w http.ResponseWriter, r *http.Request) (bool, bool) {
	if r.URL.Query().Get("emergency") == "true" {
		return true, true
	}

	if r.Body == nil {
		return false, true
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRotateBodyBytes)
	var body openapi.SigningKeyRotateRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		// An empty body (io.EOF) is valid and defaults to scheduled rotation;
		// any other decode error is a malformed request.
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return false, false
	}
	if body.Emergency != nil {
		return *body.Emergency, true
	}
	return false, true
}

// writeKeyRotateResponse emits the 200 JSON rotation response, mapping the
// crypto.RotateResult domain type onto the generated OpenAPI schema. Optional
// fields (old_kid, retired_at) are omitted when there was no prior active key.
func writeKeyRotateResponse(w http.ResponseWriter, result crypto.RotateResult) {
	resp := openapi.SigningKeyRotateResponse{
		NewKid:     result.NewKid,
		PromotedAt: result.PromoteAt,
	}
	if result.OldKid != "" {
		oldKid := result.OldKid
		resp.OldKid = &oldKid
	}
	if !result.RetireOldAt.IsZero() {
		retiredAt := result.RetireOldAt
		resp.RetiredAt = &retiredAt
	}
	emergency := result.Emergency
	resp.IsEmergency = &emergency

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// WriteHeader(200) was already sent — status cannot be changed. Log at
		// Warn: this is almost always a client disconnect, not a server bug.
		slog.Default().Warn("oidcapi: failed to encode key rotate response", "error", err)
	}
}
