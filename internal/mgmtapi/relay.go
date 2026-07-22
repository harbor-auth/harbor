package mgmtapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/harbor/harbor/internal/region"
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

// BYODomainStore is the interface for BYO-domain persistence.
// This is a narrow interface to keep the HTTP layer testable.
type BYODomainStore interface {
	// CreateDomain persists a new BYO-domain challenge.
	CreateDomain(ctx context.Context, domain *relay.BYODomain) error
	// GetDomainByName retrieves a domain by its name and user ID.
	GetDomainByName(ctx context.Context, userID, domain string) (*relay.BYODomain, error)
	// ListDomainsByUser returns all BYO-domains for a user.
	ListDomainsByUser(ctx context.Context, userID string) ([]*relay.BYODomain, error)
	// UpdateDomainState updates the state of a domain.
	UpdateDomainState(ctx context.Context, domainID string, state relay.BYODomainState) error
	// DeleteDomain removes a domain.
	DeleteDomain(ctx context.Context, domainID string) error
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

// BYODomainRequest is the JSON request body for POST /byo-domains.
type BYODomainRequest struct {
	Domain string `json:"domain"`
}

// BYODomainResponse is the JSON representation of a BYO-domain.
type BYODomainResponse struct {
	ID         string  `json:"id"`
	Domain     string  `json:"domain"`
	State      string  `json:"state"`
	Region     string  `json:"region"`
	TXTRecord  string  `json:"txt_record,omitempty"`
	MXRecord   string  `json:"mx_record,omitempty"`
	SPFRecord  string  `json:"spf_record,omitempty"`
	DKIMRecord string  `json:"dkim_record,omitempty"`
	CreatedAt  string  `json:"created_at"`
	VerifiedAt *string `json:"verified_at,omitempty"`
	ExpiresAt  string  `json:"expires_at,omitempty"`
}

// BYODomainsListResponse is the JSON envelope for GET /byo-domains.
type BYODomainsListResponse struct {
	Domains []BYODomainResponse `json:"domains"`
}

// DNSSetupStatusResponse is the JSON representation of DNS setup validation results.
type DNSSetupStatusResponse struct {
	MXValid    bool     `json:"mx_valid"`
	MXRecords  []string `json:"mx_records,omitempty"`
	SPFValid   bool     `json:"spf_valid"`
	SPFRecord  string   `json:"spf_record,omitempty"`
	DKIMValid  bool     `json:"dkim_valid"`
	DKIMRecord string   `json:"dkim_record,omitempty"`
	AllValid   bool     `json:"all_valid"`
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

// PostBYODomain handles POST /byo-domains — initiates BYO-domain verification.
// Creates a new domain challenge and returns the TXT record the user must publish.
func (s *Server) PostBYODomain(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointRelay, outcome, start) }()

	userID := r.Header.Get(UserIDHeader)
	if userID == "" {
		recordError(telemetry.EndpointRelay, "unauthorized")
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "user authentication required")
		return
	}

	if s.byoDomains == nil {
		recordError(telemetry.EndpointRelay, "service_unavailable")
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "BYO-domain service not configured")
		return
	}

	// Parse request body
	var req BYODomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		recordError(telemetry.EndpointRelay, "invalid_request")
		s.writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}

	if req.Domain == "" {
		recordError(telemetry.EndpointRelay, "invalid_request")
		s.writeError(w, http.StatusBadRequest, "invalid_request", "domain is required")
		return
	}

	// Parse user ID
	parsedUserID, err := uuid.Parse(userID)
	if err != nil {
		recordError(telemetry.EndpointRelay, "invalid_request")
		s.writeError(w, http.StatusBadRequest, "invalid_request", "invalid user ID")
		return
	}

	// Get user's region (default to EU for now; in production this would come from user profile)
	userRegion := region.EU
	if regHeader := r.Header.Get("X-Harbor-Region"); regHeader != "" {
		if parsed, err := region.Resolve(regHeader); err == nil {
			userRegion = parsed
		}
	}

	// Check if domain already exists for this user
	existing, err := s.byoDomains.GetDomainByName(r.Context(), userID, req.Domain)
	if err == nil && existing != nil {
		// Domain already exists
		if existing.State == relay.BYODomainStatePending || existing.State == relay.BYODomainStateVerified {
			// Return existing challenge
			outcome = telemetry.OutcomeSuccess
			s.writeJSON(w, http.StatusOK, byoDomainToResponse(existing, s.mtaDomain, s.relayDomain))
			return
		}
		if existing.State == relay.BYODomainStateActive {
			recordError(telemetry.EndpointRelay, "conflict")
			s.writeError(w, http.StatusConflict, "conflict", "domain is already verified and active")
			return
		}
	}

	// Generate new challenge
	domain, err := relay.GenerateChallenge(parsedUserID, req.Domain, userRegion)
	if err != nil {
		if errors.Is(err, relay.ErrDomainInvalid) || errors.Is(err, relay.ErrDomainEmpty) {
			recordError(telemetry.EndpointRelay, "invalid_request")
			s.writeError(w, http.StatusBadRequest, "invalid_request", "invalid domain format")
			return
		}
		s.logger.ErrorContext(r.Context(), "mgmtapi: generate challenge failed", "error", err)
		recordError(telemetry.EndpointRelay, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to generate challenge")
		return
	}

	// Persist the challenge
	if err := s.byoDomains.CreateDomain(r.Context(), domain); err != nil {
		if errors.Is(err, relay.ErrDomainAlreadyExists) {
			recordError(telemetry.EndpointRelay, "conflict")
			s.writeError(w, http.StatusConflict, "conflict", "domain already registered")
			return
		}
		s.logger.ErrorContext(r.Context(), "mgmtapi: create domain failed", "error", err)
		recordError(telemetry.EndpointRelay, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to create domain")
		return
	}

	outcome = telemetry.OutcomeSuccess
	s.writeJSON(w, http.StatusCreated, byoDomainToResponse(domain, s.mtaDomain, s.relayDomain))
}

// GetBYODomains handles GET /byo-domains — returns all BYO-domains for the user.
func (s *Server) GetBYODomains(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointRelay, outcome, start) }()

	userID := r.Header.Get(UserIDHeader)
	if userID == "" {
		recordError(telemetry.EndpointRelay, "unauthorized")
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "user authentication required")
		return
	}

	if s.byoDomains == nil {
		recordError(telemetry.EndpointRelay, "service_unavailable")
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "BYO-domain service not configured")
		return
	}

	domains, err := s.byoDomains.ListDomainsByUser(r.Context(), userID)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: list domains failed", "error", err)
		recordError(telemetry.EndpointRelay, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to retrieve domains")
		return
	}

	resp := BYODomainsListResponse{
		Domains: make([]BYODomainResponse, len(domains)),
	}
	for i, d := range domains {
		resp.Domains[i] = byoDomainToResponse(d, s.mtaDomain, s.relayDomain)
	}

	outcome = telemetry.OutcomeSuccess
	s.writeJSON(w, http.StatusOK, resp)
}

// PostBYODomainVerify handles POST /byo-domains/{domain}/verify — verifies TXT challenge.
func (s *Server) PostBYODomainVerify(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointRelay, outcome, start) }()

	userID := r.Header.Get(UserIDHeader)
	if userID == "" {
		recordError(telemetry.EndpointRelay, "unauthorized")
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "user authentication required")
		return
	}

	domainName := r.PathValue("domain")
	if domainName == "" {
		recordError(telemetry.EndpointRelay, "invalid_request")
		s.writeError(w, http.StatusBadRequest, "invalid_request", "domain is required")
		return
	}

	if s.byoDomains == nil || s.domainVerifier == nil {
		recordError(telemetry.EndpointRelay, "service_unavailable")
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "BYO-domain service not configured")
		return
	}

	// Look up the domain
	domain, err := s.byoDomains.GetDomainByName(r.Context(), userID, domainName)
	if err != nil {
		if errors.Is(err, relay.ErrDomainNotFound) {
			recordError(telemetry.EndpointRelay, "not_found")
			s.writeError(w, http.StatusNotFound, "not_found", "domain not found")
			return
		}
		s.logger.ErrorContext(r.Context(), "mgmtapi: get domain failed", "error", err)
		recordError(telemetry.EndpointRelay, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to retrieve domain")
		return
	}

	// Verify the TXT challenge
	err = s.domainVerifier.VerifyTXTChallenge(r.Context(), domain)
	if err != nil {
		switch {
		case errors.Is(err, relay.ErrChallengeExpired):
			recordError(telemetry.EndpointRelay, "expired")
			s.writeError(w, http.StatusGone, "expired", "challenge has expired, please request a new one")
		case errors.Is(err, relay.ErrChallengeNotFound):
			recordError(telemetry.EndpointRelay, "invalid_state")
			s.writeError(w, http.StatusConflict, "invalid_state", "domain is not in pending state")
		case errors.Is(err, relay.ErrTXTRecordNotFound):
			recordError(telemetry.EndpointRelay, "verification_failed")
			s.writeError(w, http.StatusUnprocessableEntity, "verification_failed", "TXT record not found")
		case errors.Is(err, relay.ErrTXTRecordMismatch):
			recordError(telemetry.EndpointRelay, "verification_failed")
			s.writeError(w, http.StatusUnprocessableEntity, "verification_failed", "TXT record does not match challenge")
		case errors.Is(err, relay.ErrDNSLookupFailed):
			recordError(telemetry.EndpointRelay, "dns_error")
			s.writeError(w, http.StatusBadGateway, "dns_error", "DNS lookup failed, please try again")
		default:
			s.logger.ErrorContext(r.Context(), "mgmtapi: verify challenge failed", "error", err)
			recordError(telemetry.EndpointRelay, "server_error")
			s.writeError(w, http.StatusInternalServerError, "server_error", "verification failed")
		}
		return
	}

	// Update domain state in store
	if err := s.byoDomains.UpdateDomainState(r.Context(), domain.ID.String(), relay.BYODomainStateVerified); err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: update domain state failed", "error", err)
		recordError(telemetry.EndpointRelay, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to update domain state")
		return
	}

	outcome = telemetry.OutcomeSuccess
	s.writeJSON(w, http.StatusOK, byoDomainToResponse(domain, s.mtaDomain, s.relayDomain))
}

// GetBYODomainDNSStatus handles GET /byo-domains/{domain}/dns-status — checks MX/SPF/DKIM setup.
func (s *Server) GetBYODomainDNSStatus(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointRelay, outcome, start) }()

	userID := r.Header.Get(UserIDHeader)
	if userID == "" {
		recordError(telemetry.EndpointRelay, "unauthorized")
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "user authentication required")
		return
	}

	domainName := r.PathValue("domain")
	if domainName == "" {
		recordError(telemetry.EndpointRelay, "invalid_request")
		s.writeError(w, http.StatusBadRequest, "invalid_request", "domain is required")
		return
	}

	if s.byoDomains == nil || s.domainVerifier == nil {
		recordError(telemetry.EndpointRelay, "service_unavailable")
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "BYO-domain service not configured")
		return
	}

	// Verify domain belongs to user
	domain, err := s.byoDomains.GetDomainByName(r.Context(), userID, domainName)
	if err != nil {
		if errors.Is(err, relay.ErrDomainNotFound) {
			recordError(telemetry.EndpointRelay, "not_found")
			s.writeError(w, http.StatusNotFound, "not_found", "domain not found")
			return
		}
		s.logger.ErrorContext(r.Context(), "mgmtapi: get domain failed", "error", err)
		recordError(telemetry.EndpointRelay, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to retrieve domain")
		return
	}

	// Check DNS setup
	status, err := s.domainVerifier.ValidateDNSSetup(r.Context(), domain.Domain)
	if err != nil {
		if errors.Is(err, relay.ErrDNSLookupFailed) {
			recordError(telemetry.EndpointRelay, "dns_error")
			s.writeError(w, http.StatusBadGateway, "dns_error", "DNS lookup failed, please try again")
			return
		}
		s.logger.ErrorContext(r.Context(), "mgmtapi: validate DNS failed", "error", err)
		recordError(telemetry.EndpointRelay, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "DNS validation failed")
		return
	}

	// If all valid and domain is verified, activate it
	if status.AllValid && domain.State == relay.BYODomainStateVerified {
		if err := domain.ActivateDomain(); err == nil {
			if err := s.byoDomains.UpdateDomainState(r.Context(), domain.ID.String(), relay.BYODomainStateActive); err != nil {
				s.logger.ErrorContext(r.Context(), "mgmtapi: activate domain failed", "error", err)
				// Non-fatal, continue with response
			}
		}
	}

	resp := DNSSetupStatusResponse{
		MXValid:    status.MXValid,
		MXRecords:  status.MXRecords,
		SPFValid:   status.SPFValid,
		SPFRecord:  status.SPFRecord,
		DKIMValid:  status.DKIMValid,
		DKIMRecord: status.DKIMRecord,
		AllValid:   status.AllValid,
	}

	outcome = telemetry.OutcomeSuccess
	s.writeJSON(w, http.StatusOK, resp)
}

// DeleteBYODomain handles DELETE /byo-domains/{domain} — removes a BYO-domain.
func (s *Server) DeleteBYODomain(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointRelay, outcome, start) }()

	userID := r.Header.Get(UserIDHeader)
	if userID == "" {
		recordError(telemetry.EndpointRelay, "unauthorized")
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "user authentication required")
		return
	}

	domainName := r.PathValue("domain")
	if domainName == "" {
		recordError(telemetry.EndpointRelay, "invalid_request")
		s.writeError(w, http.StatusBadRequest, "invalid_request", "domain is required")
		return
	}

	if s.byoDomains == nil {
		recordError(telemetry.EndpointRelay, "service_unavailable")
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "BYO-domain service not configured")
		return
	}

	// Look up domain to verify ownership
	domain, err := s.byoDomains.GetDomainByName(r.Context(), userID, domainName)
	if err != nil {
		if errors.Is(err, relay.ErrDomainNotFound) {
			recordError(telemetry.EndpointRelay, "not_found")
			s.writeError(w, http.StatusNotFound, "not_found", "domain not found")
			return
		}
		s.logger.ErrorContext(r.Context(), "mgmtapi: get domain failed", "error", err)
		recordError(telemetry.EndpointRelay, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to retrieve domain")
		return
	}

	// Delete the domain
	if err := s.byoDomains.DeleteDomain(r.Context(), domain.ID.String()); err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: delete domain failed", "error", err)
		recordError(telemetry.EndpointRelay, "server_error")
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to delete domain")
		return
	}

	outcome = telemetry.OutcomeSuccess
	w.WriteHeader(http.StatusNoContent)
}

// byoDomainToResponse converts a relay.BYODomain to the JSON response type.
func byoDomainToResponse(d *relay.BYODomain, mtaDomain, relayDomain string) BYODomainResponse {
	resp := BYODomainResponse{
		ID:        d.ID.String(),
		Domain:    d.Domain,
		State:     string(d.State),
		Region:    string(d.Region),
		CreatedAt: d.CreatedAt.Format(time.RFC3339),
	}

	// Include setup instructions based on state
	if d.State == relay.BYODomainStatePending {
		resp.TXTRecord = d.GetTXTRecordInstructions()
		resp.ExpiresAt = d.ExpiresAt.Format(time.RFC3339)
	}
	if d.State == relay.BYODomainStatePending || d.State == relay.BYODomainStateVerified {
		resp.MXRecord = relay.GetMXRecordInstructions(d.Domain, mtaDomain)
		resp.SPFRecord = relay.GetSPFRecordInstructions(d.Domain, relayDomain)
		resp.DKIMRecord = relay.GetDKIMRecordInstructions(d.Domain, relayDomain)
	}
	if d.VerifiedAt != nil {
		t := d.VerifiedAt.Format(time.RFC3339)
		resp.VerifiedAt = &t
	}

	return resp
}
