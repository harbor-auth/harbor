package oidcapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/gen/openapi"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

// defaultRevocationChannel is the Redis pub/sub channel that carries revoked
// JTIs to sibling harbor-hot replicas (docs/DESIGN.md §3.5).
const defaultRevocationChannel = "revocation_channel"

// RevokedJTIStore persists emergency JWT revocations to the source-of-truth
// revoked_jtis table (docs/DESIGN.md §3.5). *clients.DBRevokedJTIStore
// satisfies this interface.
type RevokedJTIStore interface {
	Insert(ctx context.Context, jti, reason string, expiresAt time.Time) (clients.RevokedJTI, error)
}

// RevocationPublisher broadcasts a revoked JTI to sibling replicas so their
// in-process bloom filters converge without waiting for the next rehydration.
// A thin adapter over *redis.Client satisfies this at wiring time.
type RevocationPublisher interface {
	Publish(ctx context.Context, channel, message string) error
}

// PostAdminRevokeJwt handles POST /admin/revoke-jwt — emergency JWT revocation
// (docs/DESIGN.md §3.5, §7.4). The pipeline is:
//
//  1. Validate the JSON body (jti, reason enum, expires_at).
//  2. Upsert the JTI into the revoked_jtis table (source of truth).
//  3. Add the JTI to this replica's bloom filter for immediate local effect.
//  4. Publish the JTI to the Redis revocation channel so sibling replicas kill
//     the token too.
//
// The DB row is the source of truth: every replica rehydrates its filter from
// revoked_jtis on startup, so a transient Redis publish failure delays — but
// never loses — cross-replica propagation. Insert is idempotent (upsert), so a
// client retry after a publish failure is safe.
func (s *Server) PostAdminRevokeJwt(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointRevoke, outcome, start) }()

	if s.revoked == nil {
		recordError(telemetry.EndpointRevoke, "server_error")
		writeError(w, http.StatusServiceUnavailable, "not_configured", "revocation endpoint is not configured")
		return
	}

	// Cap the body before decoding so a flooded admin endpoint can't exhaust
	// memory (docs/DESIGN.md §6.5). 8KB is far beyond a legitimate JTI payload.
	r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
	var body openapi.RevokeJwtRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		recordError(telemetry.EndpointRevoke, "invalid_request")
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}

	if body.Jti == "" {
		recordError(telemetry.EndpointRevoke, "invalid_request")
		writeError(w, http.StatusBadRequest, "invalid_request", "jti is required")
		return
	}
	if !validRevokeReason(body.Reason) {
		recordError(telemetry.EndpointRevoke, "invalid_request")
		writeError(w, http.StatusBadRequest, "invalid_request", "reason must be one of emergency_kill, key_rotation, user_request")
		return
	}
	if body.ExpiresAt.IsZero() {
		recordError(telemetry.EndpointRevoke, "invalid_request")
		writeError(w, http.StatusBadRequest, "invalid_request", "expires_at is required")
		return
	}

	row, err := s.revoked.Insert(r.Context(), body.Jti, string(body.Reason), body.ExpiresAt)
	if err != nil {
		// Message carries no PII (docs/DESIGN.md §6.5); details go to logs only.
		recordError(telemetry.EndpointRevoke, "server_error")
		slog.Default().Error("oidcapi: revoke-jwt insert failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to record revocation")
		return
	}

	// Apply locally first so the token is dead on this replica before the
	// pub/sub round-trip completes. Bloom Add is idempotent.
	if s.filter != nil {
		s.filter.Add(body.Jti)
	}

	// Best-effort cross-replica broadcast (see doc comment above).
	if s.publisher != nil {
		if err := s.publisher.Publish(r.Context(), s.revChannel, body.Jti); err != nil {
			slog.Default().Warn("oidcapi: revoke-jwt publish failed", "error", err)
		}
	}

	outcome = telemetry.OutcomeSuccess
	writeRevokeJwtResponse(w, row)
}

// validRevokeReason reports whether reason is one of the spec's allowed enum
// values. The generated type is an open string, so we must guard it here.
func validRevokeReason(reason openapi.RevokeJwtRequestReason) bool {
	switch reason {
	case openapi.EmergencyKill, openapi.KeyRotation, openapi.UserRequest:
		return true
	default:
		return false
	}
}

// writeRevokeJwtResponse emits the 200 JSON confirmation with no-store caching.
func writeRevokeJwtResponse(w http.ResponseWriter, row clients.RevokedJTI) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	reason := row.Reason
	resp := openapi.RevokeJwtResponse{
		Jti:       row.JTI,
		RevokedAt: row.RevokedAt,
		Reason:    &reason,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// WriteHeader(200) was already sent — status cannot be changed.
		slog.Default().Warn("oidcapi: failed to encode revoke-jwt response", "error", err)
	}
}
