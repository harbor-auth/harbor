package mgmtapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/harbor/harbor/internal/relay"
	"github.com/harbor/harbor/internal/telemetry"
)

// RelayStore is the narrow interface the relay handlers need from relay.Store.
// Depending on the interface keeps the HTTP layer unit-testable with a fake.
type RelayStore interface {
	// ListByUser returns all relay addresses for a user, ordered by most recent first.
	ListByUser(ctx context.Context, userID string) ([]*relay.Address, [][]byte, error)
	// GetByToken retrieves a relay address by its token.
	GetByToken(ctx context.Context, token string) (*relay.Address, []byte, error)
	// Deactivate sets a relay address to the deactivated state (hard-bounce kill switch).
	Deactivate(ctx context.Context, addressID string) error
}

// RelayAddressResponse is the JSON representation of a relay address
// returned by GET /relay-addresses.
type RelayAddressResponse struct {
	RelayToken    string  `json:"relay_token"`
	RelayEmail    string  `json:"relay_email"`
	ClientID      string  `json:"client_id"`
	State         string  `json:"state"`
	Region        string  `json:"region"`
	CreatedAt     string  `json:"created_at"`
	DeactivatedAt *string `json:"deactivated_at,omitempty"`
}

// RelayAddressesListResponse is the JSON envelope for GET /relay-addresses.
type RelayAddressesListResponse struct {
	Addresses []RelayAddressResponse `json:"addresses"`
}

// GetRelayAddresses handles GET /relay-addresses — returns all relay addresses
// for the authenticated user. The user ID comes from the X-Harbor-User-ID header
// set by upstream authentication. The real email is NOT returned (it is encrypted
// at rest and would require the user's DEK to decrypt); only the relay metadata
// is exposed.
func (s *Server) GetRelayAddresses(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointRelay, outcome, start) }()

	userID := r.Header.Get(UserIDHeader)
	if userID == "" {
		recordError(telemetry.EndpointRelay, "unauthorized")
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "user authentication required")
		return
	}

	if s.relays == nil {
		recordError(telemetry.EndpointRelay, "service_unavailable")
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "relay service not configured")
		return
	}

	addresses, _, err := s.relays.ListByUser(r.Context(), userID)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: relay list failed",
			"error", err)
		recordError(telemetry.EndpointRelay, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to retrieve relay addresses")
		return
	}

	resp := RelayAddressesListResponse{
		Addresses: make([]RelayAddressResponse, len(addresses)),
	}
	for i, addr := range addresses {
		resp.Addresses[i] = addressToResponse(addr)
	}

	outcome = telemetry.OutcomeSuccess
	s.writeJSON(w, http.StatusOK, resp)
}

// DeleteRelayAddress handles DELETE /relay-addresses/{relay_token} — deactivates
// the authenticated user's relay address (hard-bounce kill switch). The operation
// is scoped to the authenticated user: only the owner can deactivate their relay.
// Deactivation is independent of login grant revocation (§7.5.4): killing email
// does not revoke login, and revoking login does not deactivate the relay.
// Returns 204 on success, 404 if the token doesn't exist or doesn't belong to
// the authenticated user.
func (s *Server) DeleteRelayAddress(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointRelay, outcome, start) }()

	userID := r.Header.Get(UserIDHeader)
	if userID == "" {
		recordError(telemetry.EndpointRelay, "unauthorized")
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "user authentication required")
		return
	}

	relayToken := r.PathValue("relay_token")
	if relayToken == "" {
		recordError(telemetry.EndpointRelay, "invalid_request")
		s.writeError(w, http.StatusBadRequest, "invalid_request", "relay_token is required")
		return
	}

	if s.relays == nil {
		recordError(telemetry.EndpointRelay, "service_unavailable")
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "relay service not configured")
		return
	}

	// Look up the relay address to verify ownership before deactivating.
	addr, _, err := s.relays.GetByToken(r.Context(), relayToken)
	if err != nil {
		if errors.Is(err, relay.ErrRelayAddressNotFound) {
			recordError(telemetry.EndpointRelay, "not_found")
			s.writeError(w, http.StatusNotFound, "not_found", "relay address not found")
			return
		}
		s.logger.ErrorContext(r.Context(), "mgmtapi: relay lookup failed",
			"error", err)
		recordError(telemetry.EndpointRelay, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to deactivate relay address")
		return
	}

	// SECURITY: Verify the relay address belongs to the authenticated user.
	// This prevents cross-user deactivation attacks.
	addrUserID := uuid.UUID(addr.UserID).String()
	if addrUserID != userID {
		// Return 404 to avoid leaking existence of other users' relay addresses.
		recordError(telemetry.EndpointRelay, "not_found")
		s.writeError(w, http.StatusNotFound, "not_found", "relay address not found")
		return
	}

	// Deactivate the relay address (kill switch).
	addressID := uuid.UUID(addr.ID).String()
	if err := s.relays.Deactivate(r.Context(), addressID); err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: relay deactivate failed",
			"error", err)
		recordError(telemetry.EndpointRelay, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to deactivate relay address")
		return
	}

	// Record the kill switch event as an aggregate metric (no PII).
	RecordRelayEvent(addr.Region, false) // false = bounced/deactivated

	outcome = telemetry.OutcomeSuccess
	w.WriteHeader(http.StatusNoContent)
}

// addressToResponse converts a relay.Address to the JSON response type.
func addressToResponse(addr *relay.Address) RelayAddressResponse {
	resp := RelayAddressResponse{
		RelayToken: addr.Token,
		RelayEmail: relay.FormatEmail(addr.Token, addr.Region),
		ClientID:   addr.ClientID,
		State:      string(addr.State),
		Region:     string(addr.Region),
		CreatedAt:  addr.CreatedAt.Format(time.RFC3339),
	}
	if addr.DeactivatedAt != nil {
		t := addr.DeactivatedAt.Format(time.RFC3339)
		resp.DeactivatedAt = &t
	}
	return resp
}
