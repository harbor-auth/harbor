package mgmtapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/harbor/harbor/internal/clients"
)

// ClientManagementStore is the narrow behaviour the RFC 7592 client
// configuration endpoint (GET/PUT/DELETE /register/{client_id}) needs. It is
// satisfied by clients.DBClientRegistrationStore, so production wiring passes
// the same store used for POST /register; tests pass a small fake.
//
// VerifyRegToken is the sole authentication mechanism for these endpoints: the
// caller presents the per-client registration_access_token as a Bearer
// credential, and the store resolves it (via constant-time hash comparison) to
// exactly one client. A token therefore can only ever address its own client —
// cross-client access is structurally impossible.
type ClientManagementStore interface {
	VerifyRegToken(ctx context.Context, token string) (clients.RegisteredClient, error)
	Update(ctx context.Context, c clients.UpdateRegisteredClient) (clients.RegisteredClient, error)
	Delete(ctx context.Context, clientID string) error
}

// maxManageBody caps the RFC 7592 PUT body. It mirrors maxRegisterBody: client
// metadata is a small JSON object, so 16 KB stops a flooded update from
// exhausting memory (docs/DESIGN.md §6.5).
const maxManageBody = maxRegisterBody

// GetRegister is the RFC 7592 §2.1 client read endpoint
// (GET /register/{client_id}). It authenticates the caller via the
// registration_access_token and returns the current client configuration. The
// client_secret is never returned (only its hash is stored); a client that has
// lost its secret must re-register.
//
// Responses:
//   - 200 OK                  current client information response
//   - 401 Unauthorized        missing/invalid registration access token
//   - 403 Forbidden           token valid but not for this client_id
//   - 503 Service Unavailable management not wired (no store)
func (s *Server) GetRegister(w http.ResponseWriter, r *http.Request) {
	if s.clientMgmt == nil {
		s.managementUnavailable(w)
		return
	}
	rc, token, ok := s.authorizeClientManagement(w, r)
	if !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, s.clientConfigResponse(rc, token))
}

// PutRegister is the RFC 7592 §2.2 client update endpoint
// (PUT /register/{client_id}). It authenticates via the
// registration_access_token, re-validates the submitted metadata, and replaces
// the mutable fields. Immutable fields (client_id, sector_id, created_at) and
// the credentials (client_secret, registration_access_token) are preserved —
// this endpoint updates metadata, it does not rotate secrets.
//
// Responses:
//   - 200 OK                  updated client information response
//   - 400 Bad Request         malformed body or invalid client metadata
//   - 401 Unauthorized        missing/invalid registration access token
//   - 403 Forbidden           token valid but not for this client_id
//   - 503 Service Unavailable management not wired (no store)
//   - 500 Internal Server Error persistence failure
func (s *Server) PutRegister(w http.ResponseWriter, r *http.Request) {
	if s.clientMgmt == nil {
		s.managementUnavailable(w)
		return
	}
	rc, token, ok := s.authorizeClientManagement(w, r)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxManageBody)
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON request body")
		return
	}

	meta := ClientMetadata{
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		Scopes:                  strings.Fields(req.Scope),
		ClientName:              req.ClientName,
	}
	if err := ValidateClientMetadata(meta); err != nil {
		s.writeError(w, http.StatusBadRequest, registrationErrorCode(err), err.Error())
		return
	}

	// Apply RFC 7591 §2 defaults so the stored row stays fully specified.
	grantTypes := meta.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{defaultGrantType}
	}
	responseTypes := meta.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{defaultResponseType}
	}
	authMethod := meta.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = defaultAuthMethod
	}

	updated, err := s.clientMgmt.Update(r.Context(), clients.UpdateRegisteredClient{
		ClientID:      rc.ClientID,
		Name:          meta.ClientName,
		RedirectURIs:  meta.RedirectURIs,
		TokenFormat:   rc.TokenFormat,
		ScopesAllowed: meta.Scopes,
		// Credentials are preserved: PUT updates metadata only. We re-hash the
		// presented (validated) token rather than storing a new one, and keep the
		// existing client_secret hash untouched.
		ClientSecretHash:            rc.ClientSecretHash,
		RegistrationAccessTokenHash: HashSecret(token),
		GrantTypes:                  grantTypes,
		ResponseTypes:               responseTypes,
		TokenEndpointAuthMethod:     authMethod,
	})
	if err != nil {
		if errors.Is(err, clients.ErrClientNotFound) {
			// The client was deleted between authentication and update. Surface a
			// 401 (the token no longer resolves to a client) rather than leaking
			// that the client_id once existed.
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			s.writeError(w, http.StatusUnauthorized, "invalid_token",
				"a valid registration access token is required")
			return
		}
		s.registrationServerError(w, r, "update client", err)
		return
	}

	s.writeJSON(w, http.StatusOK, s.clientConfigResponse(updated, token))
}

// DeleteRegister is the RFC 7592 §2.3 client delete endpoint
// (DELETE /register/{client_id}). It authenticates via the
// registration_access_token and removes the client. Deleting the client cascades
// to its consent grants at the DB level (migration 0012 FK ON DELETE CASCADE),
// which the revocation outbox/subscriber (internal/clients) then propagates to
// revoke any live tokens — so a deleted client's sessions are torn down without
// the handler touching the revocation stack directly.
//
// Responses:
//   - 204 No Content          client deleted
//   - 401 Unauthorized        missing/invalid registration access token
//   - 403 Forbidden           token valid but not for this client_id
//   - 503 Service Unavailable management not wired (no store)
//   - 500 Internal Server Error persistence failure
func (s *Server) DeleteRegister(w http.ResponseWriter, r *http.Request) {
	if s.clientMgmt == nil {
		s.managementUnavailable(w)
		return
	}
	rc, _, ok := s.authorizeClientManagement(w, r)
	if !ok {
		return
	}
	if err := s.clientMgmt.Delete(r.Context(), rc.ClientID); err != nil {
		s.registrationServerError(w, r, "delete client", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// authorizeClientManagement authenticates an RFC 7592 request. It resolves the
// Bearer registration_access_token to a client (constant-time inside the store)
// and enforces that the resolved client matches the {client_id} path segment.
// On failure it writes the appropriate error (401 for an absent/invalid token,
// 403 for a valid token addressing a different client — never leaking whether
// the path client exists) and returns ok=false. On success it returns the
// client, the plaintext token (for echoing in the response), and ok=true.
func (s *Server) authorizeClientManagement(w http.ResponseWriter, r *http.Request) (clients.RegisteredClient, string, bool) {
	token := bearerToken(r)
	rc, err := s.clientMgmt.VerifyRegToken(r.Context(), token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		s.writeError(w, http.StatusUnauthorized, "invalid_token",
			"a valid registration access token is required")
		return clients.RegisteredClient{}, "", false
	}
	if rc.ClientID != r.PathValue("client_id") {
		// The token authenticates a real client, but not the one named in the
		// path. Refuse without confirming or denying the path client's existence.
		s.writeError(w, http.StatusForbidden, "invalid_token",
			"the registration access token is not authorized for this client")
		return clients.RegisteredClient{}, "", false
	}
	return rc, token, true
}

// managementUnavailable renders the 503 returned when the RFC 7592 endpoints
// are not wired (no management store).
func (s *Server) managementUnavailable(w http.ResponseWriter) {
	s.writeError(w, http.StatusServiceUnavailable, "unavailable",
		"dynamic client registration is not configured on this instance")
}

// clientConfigResponse builds the RFC 7592 §3 client information response for a
// read/update. It echoes the presented registration_access_token (which is
// unchanged by GET/PUT) and never includes a client_secret, since only its hash
// is persisted.
func (s *Server) clientConfigResponse(rc clients.RegisteredClient, regToken string) registerResponse {
	return registerResponse{
		ClientID:                rc.ClientID,
		ClientIDIssuedAt:        issuedAt(rc, time.Now().UTC()),
		RegistrationAccessToken: regToken,
		RegistrationClientURI:   s.registrationClientURI(rc.ClientID),
		RedirectURIs:            rc.RedirectURIs,
		GrantTypes:              rc.GrantTypes,
		ResponseTypes:           rc.ResponseTypes,
		TokenEndpointAuthMethod: rc.TokenEndpointAuthMethod,
		ClientName:              rc.Name,
		Scope:                   strings.Join(rc.ScopesAllowed, " "),
	}
}
