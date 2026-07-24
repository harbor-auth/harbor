package mgmtapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/crypto"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

const (
	// auditDefaultLimit is the default page size for GET /audit-events.
	auditDefaultLimit = 50
	// auditMaxLimit caps the per-request page size to prevent memory exhaustion.
	auditMaxLimit = 100
)

// RawAuditEvent is a type alias for clients.RawAuditEvent. The struct is
// defined in the clients package to avoid an import cycle (mgmtapi/register.go
// already imports clients, so clients cannot import mgmtapi). Using a true
// alias keeps all handler and test code unchanged.
type RawAuditEvent = clients.RawAuditEvent

// AuditStore lists encrypted audit events for a user, newest-first, with
// limit/offset pagination. Satisfied by an adapter over *db.Queries
// (ListAuditEventsByUserWithPayload).
type AuditStore interface {
	ListAuditEvents(ctx context.Context, userID string, limit, offset int) ([]RawAuditEvent, error)
}

// AuditUserReader loads the region and wrapped DEK for a user. Satisfied by an
// adapter over the users table (same data that identity.AuditUserLoader reads).
type AuditUserReader interface {
	LoadUserForAudit(ctx context.Context, userID string) (region string, dekWrapped []byte, err error)
}

// AuditKeyUnwrapper unwraps a per-user DEK under the regional KEK. Satisfied
// by crypto.KeyProvider.
type AuditKeyUnwrapper interface {
	UnwrapDEK(ctx context.Context, region string, wrapped []byte) (crypto.DEK, error)
}

// AuditDecryptor opens an envelope-encrypted payload under a DEK. Satisfied by
// *crypto.Cipher.
type AuditDecryptor interface {
	Decrypt(dek crypto.DEK, ciphertext, aad []byte) ([]byte, error)
}

// AuditTrailDeps bundles the read-path dependencies for GET /audit-events.
// All fields are required; a nil AuditTrailDeps causes the endpoint to return
// 503 Service Unavailable.
type AuditTrailDeps struct {
	Store     AuditStore
	Users     AuditUserReader
	Keys      AuditKeyUnwrapper
	Decryptor AuditDecryptor
}

// auditEventResponse is the JSON representation of a single decrypted event.
type auditEventResponse struct {
	ID         string          `json:"id"`
	EventType  string          `json:"event_type"`
	ClientID   *string         `json:"client_id,omitempty"`
	OccurredAt string          `json:"occurred_at"` // RFC3339
	Detail     json.RawMessage `json:"detail,omitempty"`
}

// auditEventsListResponse is the JSON envelope for GET /audit-events.
type auditEventsListResponse struct {
	Events []auditEventResponse `json:"events"`
}

// auditPayloadAAD returns the GCM additional data for a per-event payload.
// MUST match identity.auditPayloadAAD used at write time (identity/audit.go).
func auditPayloadAAD(userID string) []byte {
	return []byte("harbor-audit-payload-v1:" + userID)
}

// GetAuditEvents handles GET /audit-events — returns the authenticated user's
// envelope-decrypted audit log, newest-first, with limit/offset pagination
// (DESIGN §10, §11.6).
//
// Decryption uses the user's own DEK, so the operator never sees plaintext
// detail — only event_type + timestamp remain visible in the DB row. A failed
// decryption (e.g. after crypto-shred) returns the event with no detail field
// rather than an error, so the user still sees the event skeleton.
//
// Query params:
//   - limit  int  (default 50, max 100)
//   - offset int  (default 0)
//
// Responses:
//   - 200 OK                  on success ({events: [...]})
//   - 401 Unauthorized        missing X-Harbor-User-ID
//   - 503 Service Unavailable audit trail not configured
//   - 500 Internal Server Error DB or crypto failure
func (s *Server) GetAuditEvents(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointAudit, outcome, start) }()

	userID := r.Header.Get(UserIDHeader)
	if userID == "" {
		recordError(telemetry.EndpointAudit, "unauthorized")
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "user authentication required")
		return
	}

	if s.auditTrail == nil {
		recordError(telemetry.EndpointAudit, "service_unavailable")
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "audit trail not configured")
		return
	}

	// Parse pagination query params; clamp to safe bounds.
	limit := auditDefaultLimit
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			if n > auditMaxLimit {
				n = auditMaxLimit
			}
			limit = n
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			offset = n
		}
	}

	// Load user's region + wrapped DEK so we can open the ciphertext.
	region, dekWrapped, err := s.auditTrail.Users.LoadUserForAudit(r.Context(), userID)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: audit: load user failed", "error", err)
		recordError(telemetry.EndpointAudit, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to retrieve audit events")
		return
	}

	// Unwrap the DEK. A KEK or crypto failure is a 500 — not 401 — because the
	// user is already authenticated; a failing DEK unwrap is a server-side issue.
	dek, err := s.auditTrail.Keys.UnwrapDEK(r.Context(), region, dekWrapped)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: audit: DEK unwrap failed", "error", err)
		recordError(telemetry.EndpointAudit, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to retrieve audit events")
		return
	}

	// Query the paginated event rows (payload_encrypted included).
	rows, err := s.auditTrail.Store.ListAuditEvents(r.Context(), userID, limit, offset)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: audit: list events failed", "error", err)
		recordError(telemetry.EndpointAudit, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to retrieve audit events")
		return
	}

	aad := auditPayloadAAD(userID)
	events := make([]auditEventResponse, 0, len(rows))
	for _, row := range rows {
		ev := auditEventResponse{
			ID:         row.ID,
			EventType:  row.EventType,
			ClientID:   row.ClientID,
			OccurredAt: row.OccurredAt.UTC().Format(time.RFC3339),
		}
		// Decrypt the payload when present. A nil/empty ciphertext is valid for
		// rows written before migration 0013 or events without sensitive detail.
		// A decryption failure (e.g. after crypto-shred via DEK destruction)
		// is logged at Warn and the event is returned skeleton-only — the user
		// still sees the event_type + timestamp (DESIGN §4.4, §11.6).
		if len(row.PayloadEncrypted) > 0 {
			pt, decErr := s.auditTrail.Decryptor.Decrypt(dek, row.PayloadEncrypted, aad)
			if decErr != nil {
				s.logger.WarnContext(r.Context(),
					"mgmtapi: audit: decrypt payload failed — event returned without detail",
					"event_type", row.EventType, "error", decErr)
			} else if len(pt) > 0 {
				ev.Detail = json.RawMessage(pt)
			}
		}
		events = append(events, ev)
	}

	outcome = telemetry.OutcomeSuccess
	s.writeJSON(w, http.StatusOK, auditEventsListResponse{Events: events})
}
