package mgmtapi

import (
	"context"
	"net/http"
	"time"

	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/harbor-auth/harbor/internal/oidc"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

// ConsentAuditRecorder records consent-lifecycle audit events on a best-effort
// basis (consent.granted, consent.revoked). It is satisfied directly by
// *identity.AuditRecorder. Emission is always non-blocking (RecordAsync
// detaches from the request context) so a slow/failing audit write never
// stalls the consent management path (DESIGN §2.1, Decision 3).
type ConsentAuditRecorder interface {
	RecordAsync(ctx context.Context, userID string, et identity.EventType, clientID *string, detail any)
}

// ConsentStore is the narrow interface the consent handlers need from
// oidc.ConsentStore. Depending on the interface keeps the HTTP layer
// unit-testable with a fake.
type ConsentStore interface {
	// FindGrant returns the active grant for a (userID, clientID) pair. found=false
	// means the user has no active grant for that client.
	FindGrant(ctx context.Context, userID, clientID string) (oidc.Grant, bool, error)
	// ListGrantsByUser returns all active grants for a user (newest first).
	ListGrantsByUser(ctx context.Context, userID string) ([]oidc.Grant, error)
	// RevokeGrantAndSessions atomically disconnects an app and reports whether
	// this request won the active-grant race.
	RevokeGrantAndSessions(ctx context.Context, id string) (bool, error)
}

// SessionRevoker cascades consent revocation to active refresh-token sessions.
// Revoking a consent grant should also tear down any sessions the user has with
// that RP so the app cannot silently continue via refresh tokens
// (docs/DESIGN.md §11.3). Satisfied by clients.DBSessionStore.
type SessionRevoker interface {
	RevokeSessionsByUserClient(ctx context.Context, userID, clientID string) error
}

// ConsentGrantResponse is the JSON representation of a consent grant
// returned by GET /consent-grants.
type ConsentGrantResponse struct {
	ID        string   `json:"id"`
	ClientID  string   `json:"client_id"`
	Scopes    []string `json:"scopes"`
	GrantedAt string   `json:"granted_at"` // RFC3339 format
}

// ConsentGrantsListResponse is the JSON envelope for GET /consent-grants.
type ConsentGrantsListResponse struct {
	Grants []ConsentGrantResponse `json:"grants"`
}

// GetConsentGrants handles GET /consent-grants — returns all active consent
// grants for the authenticated user. The caller identity is resolved from the
// BFF session context.
func (s *Server) GetConsentGrants(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointConsent, outcome, start) }()

	userID, ok := s.callerID(w, r, telemetry.EndpointConsent)
	if !ok {
		return
	}

	if s.consents == nil {
		recordError(telemetry.EndpointConsent, "service_unavailable")
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "consent service not configured")
		return
	}

	grants, err := s.consents.ListGrantsByUser(r.Context(), userID)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: consent list failed",
			"error", err)
		recordError(telemetry.EndpointConsent, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to retrieve consent grants")
		return
	}

	resp := ConsentGrantsListResponse{
		Grants: make([]ConsentGrantResponse, len(grants)),
	}
	for i, g := range grants {
		resp.Grants[i] = ConsentGrantResponse{
			ID:        g.ID,
			ClientID:  g.ClientID,
			Scopes:    g.Scopes,
			GrantedAt: g.CreatedAt.Format(time.RFC3339),
		}
	}

	outcome = telemetry.OutcomeSuccess
	s.writeJSON(w, http.StatusOK, resp)
}

// DeleteConsentGrant handles DELETE /consent-grants/{client_id} — revokes the
// authenticated user's consent grant for the given RP and cascades the
// revocation to any active sessions with that RP. The operation is idempotent:
// it returns 204 even when no active grant exists so repeated calls (or races)
// are safe. Users can only revoke their own grants — the lookup is scoped by
// the authenticated BFF session caller.
func (s *Server) DeleteConsentGrant(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointConsent, outcome, start) }()

	userID, ok := s.callerID(w, r, telemetry.EndpointConsent)
	if !ok {
		return
	}

	clientID := r.PathValue("client_id")
	if clientID == "" {
		recordError(telemetry.EndpointConsent, "invalid_request")
		s.writeError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}

	if s.consents == nil {
		recordError(telemetry.EndpointConsent, "service_unavailable")
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "consent service not configured")
		return
	}

	// Look up the grant scoped to this user so we (a) confirm ownership and
	// (b) obtain the grant ID needed to revoke. A missing grant is not an
	// error — revocation is idempotent.
	grant, found, err := s.consents.FindGrant(r.Context(), userID, clientID)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: consent lookup failed",
			"error", err)
		recordError(telemetry.EndpointConsent, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to revoke consent grant")
		return
	}

	if found {
		revoked, err := s.consents.RevokeGrantAndSessions(r.Context(), grant.ID)
		if err != nil {
			s.logger.ErrorContext(r.Context(), "mgmtapi: consent revoke failed",
				"error", err)
			recordError(telemetry.EndpointConsent, "server_error")
			s.writeError(w, http.StatusInternalServerError, "server_error", "failed to revoke consent grant")
			return
		}

		// Best-effort audit emission: consent.revoked records the user
		// disconnecting an RP. Emitted only when an active grant was found and
		// revoked. RecordAsync is non-blocking and never fails the request.
		if revoked && s.consentAudit != nil {
			cid := clientID
			s.consentAudit.RecordAsync(r.Context(), userID, identity.EventConsentRevoked, &cid, nil)
		}
	}

	outcome = telemetry.OutcomeSuccess
	w.WriteHeader(http.StatusNoContent)
}
