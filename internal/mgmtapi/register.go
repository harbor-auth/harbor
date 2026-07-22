package mgmtapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

// ClientRegistrationStore is the narrow behaviour the POST /register handler
// needs to persist a dynamically-registered client. Depending on the interface
// (not clients.DBClientRegistrationStore directly) keeps the HTTP layer
// unit-testable with a fake and free of DB wiring.
type ClientRegistrationStore interface {
	Create(ctx context.Context, c clients.NewRegisteredClient) (clients.RegisteredClient, error)
}

// maxRegisterBody caps the registration request body. Client metadata is a
// small JSON object (a handful of redirect URIs, a name, some arrays), so 16 KB
// is far beyond any legitimate request and stops a flooded /register from
// exhausting memory (docs/DESIGN.md §6.5).
const maxRegisterBody = 16 * 1024

// Registration defaults (RFC 7591 §2). Applied AFTER validation when a client
// omits the field, so the stored row is always fully specified.
const (
	defaultGrantType    = "authorization_code"
	defaultResponseType = "code"
	defaultAuthMethod   = "client_secret_basic"
	// authMethodNone marks a public client — no client_secret is minted or stored.
	authMethodNone = "none"
	// defaultTokenFormat is the token_format stored for dynamically-registered
	// clients. Harbor issues JWT access tokens (docs/DESIGN.md §3.3).
	defaultTokenFormat = "jwt"
)

// registerRequest is the RFC 7591 §2 client-metadata request body. `scope` is a
// single space-delimited string per the RFC (not a JSON array).
type registerRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

// registerResponse is the RFC 7591 §3.2.1 client-information response. The
// plaintext client_secret and registration_access_token are returned EXACTLY
// ONCE here — only their hashes are persisted, so a lost secret means the client
// must re-register.
type registerResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   *int64   `json:"client_secret_expires_at,omitempty"`
	RegistrationAccessToken string   `json:"registration_access_token"`
	RegistrationClientURI   string   `json:"registration_client_uri"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ClientName              string   `json:"client_name,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

// PostRegister is the RFC 7591 dynamic client registration endpoint
// (POST /register). It validates the submitted metadata, mints a fresh
// client_id, a registration_access_token (RFC 7592), and — for confidential
// clients — a client_secret, persists the HASHES, and returns the plaintext
// credentials once alongside the registration_client_uri.
//
// Responses:
//   - 201 Created             on success (client information response)
//   - 400 Bad Request         malformed body or invalid client metadata
//   - 401 Unauthorized        missing/invalid initial access token (when gated)
//   - 503 Service Unavailable registration not wired (no store)
//   - 500 Internal Server Error credential minting or persistence failure
func (s *Server) PostRegister(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := telemetry.OutcomeError
	defer func() { recordRequest(telemetry.EndpointRegister, outcome, start) }()

	if s.clientReg == nil {
		recordError(telemetry.EndpointRegister, "unavailable")
		s.writeError(w, http.StatusServiceUnavailable, "unavailable",
			"dynamic client registration is not configured on this instance")
		return
	}

	// Optional initial-access-token gate (RFC 7591 §1.2). When configured, a
	// caller must present the token as a Bearer credential; otherwise we return
	// 401 BEFORE reading the body, so an unauthorized request persists nothing.
	if !s.initialAccessTokenAuthorized(r) {
		recordError(telemetry.EndpointRegister, "invalid_token")
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		s.writeError(w, http.StatusUnauthorized, "invalid_token",
			"a valid initial access token is required to register a client")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRegisterBody)
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		recordError(telemetry.EndpointRegister, "invalid_request")
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
		recordError(telemetry.EndpointRegister, registrationErrorCode(err))
		s.writeError(w, http.StatusBadRequest, registrationErrorCode(err), err.Error())
		return
	}

	// Apply RFC 7591 §2 defaults so the persisted row is fully specified.
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

	// Mint credentials. client_id and the registration_access_token are always
	// issued; a client_secret is issued only for confidential clients (a public
	// client — token_endpoint_auth_method "none" — is PKCE-protected instead).
	clientID, err := MintClientID()
	if err != nil {
		s.registrationServerError(w, r, "mint client_id", err)
		return
	}
	regToken, err := MintRegistrationAccessToken()
	if err != nil {
		s.registrationServerError(w, r, "mint registration_access_token", err)
		return
	}
	var clientSecret string
	if authMethod != authMethodNone {
		clientSecret, err = MintClientSecret()
		if err != nil {
			s.registrationServerError(w, r, "mint client_secret", err)
			return
		}
	}

	// Hash before persistence — the plaintext credentials never touch the DB.
	var secretHash []byte
	if clientSecret != "" {
		secretHash = HashSecret(clientSecret)
	}
	regTokenHash := HashSecret(regToken)

	now := time.Now().UTC()
	rc, err := s.clientReg.Create(r.Context(), clients.NewRegisteredClient{
		ClientID: clientID,
		Name:     meta.ClientName,
		// Each dynamically-registered client is its own PPID sector: pairwise
		// subjects are derived per sector_id (docs/DESIGN.md §3.2), and a fresh
		// client has no shared sector_identifier_uri, so we scope it to itself.
		SectorID:                    clientID,
		RedirectURIs:                meta.RedirectURIs,
		TokenFormat:                 defaultTokenFormat,
		ScopesAllowed:               meta.Scopes,
		ClientSecretHash:            secretHash,
		RegistrationAccessTokenHash: regTokenHash,
		GrantTypes:                  grantTypes,
		ResponseTypes:               responseTypes,
		TokenEndpointAuthMethod:     authMethod,
		CreatedAt:                   now,
	})
	if err != nil {
		s.registrationServerError(w, r, "persist client", err)
		return
	}

	outcome = telemetry.OutcomeSuccess
	resp := registerResponse{
		ClientID:                rc.ClientID,
		ClientSecret:            clientSecret,
		ClientIDIssuedAt:        issuedAt(rc, now),
		RegistrationAccessToken: regToken,
		RegistrationClientURI:   s.registrationClientURI(rc.ClientID),
		RedirectURIs:            rc.RedirectURIs,
		GrantTypes:              rc.GrantTypes,
		ResponseTypes:           rc.ResponseTypes,
		TokenEndpointAuthMethod: rc.TokenEndpointAuthMethod,
		ClientName:              rc.Name,
		Scope:                   strings.Join(rc.ScopesAllowed, " "),
	}
	// RFC 7591 §3.2.1: client_secret_expires_at is REQUIRED when a client_secret
	// is issued. 0 means the secret never expires.
	if clientSecret != "" {
		neverExpires := int64(0)
		resp.ClientSecretExpiresAt = &neverExpires
	}

	s.writeJSON(w, http.StatusCreated, resp)
}

// initialAccessTokenAuthorized reports whether the request satisfies the
// optional initial-access-token gate (RFC 7591 §1.2). When no gate is
// configured (initialAccessTokenHash is nil) every request is authorized.
// Otherwise the caller must present the configured token as a Bearer
// credential; the presented token is hashed and compared in CONSTANT TIME so a
// wrong token cannot be discovered via a timing side-channel.
func (s *Server) initialAccessTokenAuthorized(r *http.Request) bool {
	if s.initialAccessTokenHash == nil {
		return true
	}
	token := bearerToken(r)
	if token == "" {
		return false
	}
	presented := HashSecret(token)
	return subtle.ConstantTimeCompare(presented, s.initialAccessTokenHash) == 1
}

// bearerToken extracts the token from an "Authorization: Bearer <token>"
// header, returning "" when the header is absent or not a Bearer credential.
// The scheme is matched case-insensitively per RFC 7235 §2.1.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(auth[len(prefix):])
}

// registrationServerError logs an internal registration failure and returns a
// generic 500 (the error may carry internal detail; docs/DESIGN.md §6.5).
func (s *Server) registrationServerError(w http.ResponseWriter, r *http.Request, stage string, err error) {
	s.logger.ErrorContext(r.Context(), "client registration failed", "stage", stage, "error", err)
	recordError(telemetry.EndpointRegister, "server_error")
	s.writeError(w, http.StatusInternalServerError, "server_error", "client registration failed")
}

// registrationClientURI builds the RFC 7592 client configuration endpoint URL
// for a client_id: {base}/register/{client_id}.
func (s *Server) registrationClientURI(clientID string) string {
	base := strings.TrimRight(s.registrationBaseURL, "/")
	return base + "/register/" + url.PathEscape(clientID)
}

// issuedAt returns the client_id_issued_at timestamp (Unix seconds), falling
// back to now if the store did not stamp created_at.
func issuedAt(rc clients.RegisteredClient, fallback time.Time) int64 {
	if rc.CreatedAt.IsZero() {
		return fallback.Unix()
	}
	return rc.CreatedAt.Unix()
}

// registrationErrorCode maps a validation error to its RFC 7591 §3.2.2 error
// code: redirect-URI failures are invalid_redirect_uri, everything else is
// invalid_client_metadata.
func registrationErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrNoRedirectURIs),
		errors.Is(err, ErrRedirectURIInvalid),
		errors.Is(err, ErrRedirectURINotHTTPS),
		errors.Is(err, ErrRedirectURIFragment):
		return "invalid_redirect_uri"
	default:
		return "invalid_client_metadata"
	}
}
