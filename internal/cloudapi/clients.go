// clients.go implements the namespace-scoped OIDC client CRUD operations of
// cloudopenapi.ServerInterface (internal/gen/openapi/cloud, generated from
// api/openapi/harbor-cloud.yaml):
// POST/GET   /admin/v1/namespaces/{namespace}/clients
// GET/PUT/DELETE /admin/v1/namespaces/{namespace}/clients/{client_id}
//
// This is the Harbor half of the cloud signup funnel: harbor-cloud calls
// these routes to provision an OIDC relying party per tenant namespace. Every
// handler follows namespaces.go's shape (bounded body read,
// validIdempotencyKey, the checkIdempotency/recordOperation ledger flow,
// writeCloudBody/writeCloudJSON/writeCloudError) — see that file's doc
// comment for the pieces this file reuses rather than redefines.
package cloudapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/harbor-auth/harbor/internal/clients"
	cloudopenapi "github.com/harbor-auth/harbor/internal/gen/openapi/cloud"
	"github.com/harbor-auth/harbor/internal/oidc"
)

// maxClientRequestBodyBytes caps a client create/update request body (a
// client_id, a handful of redirect URIs, and some short metadata strings —
// still a small JSON object even at the maximum 8 redirect_uris), preventing
// a flooded private endpoint from exhausting memory (mirrors
// maxNamespaceRequestBodyBytes).
const maxClientRequestBodyBytes = 16 * 1024

// maxClientRedirectURIs mirrors ClientCreateRequest/ClientUpdateRequest's
// redirect_uris maxItems in api/openapi/harbor-cloud.yaml. The generated
// ServerInterfaceWrapper does not enforce JSON Schema constraints at
// runtime, so the handler enforces this bound itself.
const maxClientRedirectURIs = 8

// Idempotency-ledger operation names (cloud_operations.operation), matching
// namespaceOpCreate/opNamespaceDelete's naming convention.
const (
	opClientCreate = "client.create"
	opClientUpdate = "client.update"
	opClientDelete = "client.delete"
)

// clientIDPattern matches ClientCreateRequest.client_id's documented pattern
// in api/openapi/harbor-cloud.yaml.
var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{8,128}$`)

// clientSecretHashPattern matches ClientCreateRequest/ClientUpdateRequest's
// client_secret_hash pattern: lowercase hex-encoded SHA-256 (64 hex chars).
// Uppercase hex is deliberately rejected rather than normalized — accepting
// two encodings of the same bytes would let two "different" requests hash to
// the same idempotency key while looking distinct to a byte-for-byte replay
// check, and there is no legitimate reason a caller can't just lowercase it
// before sending.
var clientSecretHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Client create defaults (api/openapi/harbor-cloud.yaml `ClientCreateRequest`),
// applied when the caller omits the field.
var (
	defaultClientGrantTypes    = []string{"authorization_code", "refresh_token"}
	defaultClientResponseTypes = []string{"code"}
)

const (
	defaultClientAuthMethod = "client_secret_basic"
	defaultClientScope      = "openid"
	// defaultClientTokenFormat mirrors mgmtapi's defaultTokenFormat — Harbor
	// issues JWT access tokens (docs/DESIGN.md §3.3) for every client,
	// namespaced or dynamically registered.
	defaultClientTokenFormat = "jwt"
)

// PostAdminV1NamespacesClients handles POST
// /admin/v1/namespaces/{namespace}/clients, requiring the `clients:write`
// scope. It is idempotent on Idempotency-Key exactly like namespace create;
// see this file's package doc for the shared ledger flow. Creating a
// client_id that already exists — under this namespace, another namespace,
// or no namespace at all — is rejected with 409 client_already_exists,
// naming neither the id nor its owner.
func (s *Server) PostAdminV1NamespacesClients(w http.ResponseWriter, r *http.Request, namespace string, params cloudopenapi.PostAdminV1NamespacesClientsParams) {
	idempotencyKey := params.IdempotencyKey
	if !validIdempotencyKey(idempotencyKey) {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", "missing or invalid Idempotency-Key header")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxClientRequestBodyBytes)
	var req cloudopenapi.ClientCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", "malformed JSON request body")
		return
	}

	if !clientIDPattern.MatchString(req.ClientId) {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", "client_id must match ^[A-Za-z0-9._~-]{8,128}$")
		return
	}
	if len(req.RedirectUris) > maxClientRedirectURIs {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", "redirect_uris must contain no more than 8 entries")
		return
	}
	if err := clients.ValidateRedirectURIs(req.RedirectUris); err != nil {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	grantTypes := defaultClientGrantTypes
	if req.GrantTypes != nil {
		grantTypes = grantTypesToStrings(*req.GrantTypes)
	}
	if err := clients.ValidateGrantTypes(grantTypes); err != nil {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	responseTypes := defaultClientResponseTypes
	if req.ResponseTypes != nil {
		responseTypes = responseTypesToStrings(*req.ResponseTypes)
	}
	if err := clients.ValidateResponseTypes(responseTypes); err != nil {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	authMethod := defaultClientAuthMethod
	if req.TokenEndpointAuthMethod != nil {
		authMethod = string(*req.TokenEndpointAuthMethod)
	}
	if err := clients.ValidateTokenEndpointAuthMethod(authMethod); err != nil {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	secretHashHex := stringOrEmpty(req.ClientSecretHash)
	if secretHashHex != "" && !clientSecretHashPattern.MatchString(secretHashHex) {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", "client_secret_hash must be 64 lowercase hex characters")
		return
	}
	if msg, ok := validateAuthMethodSecretPairing(authMethod, secretHashHex != ""); !ok {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	scope := defaultClientScope
	if req.Scope != nil {
		scope = *req.Scope
	}

	ctx := r.Context()
	reqHash, err := hashClientCreateRequest(namespace, req)
	if err != nil {
		writeInternalError(w, "cloudapi: hash client create request", err)
		return
	}

	stored, outcome, err := s.checkIdempotency(ctx, idempotencyKey, opClientCreate, reqHash)
	if err != nil {
		writeInternalError(w, "cloudapi: check client create idempotency", err)
		return
	}
	switch outcome {
	case idempotencyReplay:
		writeStoredResponse(w, stored)
		return
	case idempotencyConflict:
		writeCloudError(w, http.StatusConflict, "idempotency_key_reused", "Idempotency-Key was previously used with a different request body")
		return
	}

	if !s.namespaceActive(ctx, w, namespace) {
		return
	}

	// Pattern-validated above (64 lowercase hex chars), so this cannot fail —
	// hex.DecodeString is a format conversion, not a cryptographic transform:
	// Harbor stores exactly these bytes (docs on ClientCreateRequest.client_secret_hash).
	var secretHash []byte
	if secretHashHex != "" {
		secretHash, err = hex.DecodeString(secretHashHex)
		if err != nil {
			writeInternalError(w, "cloudapi: decode client_secret_hash", err)
			return
		}
	}

	created, err := s.clientStore.Create(ctx, clients.NewNamespacedClient{
		ClientID:    req.ClientId,
		NamespaceID: namespace,
		Name:        stringOrEmpty(req.ClientName),
		// Each namespaced client is its own PPID sector, mirroring
		// mgmtapi/register.go's dynamic registration: a fresh client has no
		// shared sector_identifier_uri, and sharing a sector across tenants
		// would let two tenants correlate the same user's pairwise subject.
		SectorID:                req.ClientId,
		RedirectURIs:            req.RedirectUris,
		TokenFormat:             defaultClientTokenFormat,
		ScopesAllowed:           strings.Fields(scope),
		ClientSecretHash:        secretHash,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: authMethod,
		CreatedAt:               time.Now().UTC(),
	})
	if err != nil {
		if errors.Is(err, clients.ErrNamespacedClientExists) {
			writeCloudError(w, http.StatusConflict, "client_already_exists", "a client with this id already exists")
			return
		}
		writeInternalError(w, "cloudapi: create namespaced client", err)
		return
	}

	body, err := json.Marshal(clientResponse(created))
	if err != nil {
		writeInternalError(w, "cloudapi: marshal client response", err)
		return
	}
	s.recordOperation(ctx, idempotencyKey, opClientCreate, reqHash, http.StatusCreated, body)
	writeCloudBody(w, http.StatusCreated, body)
}

// GetAdminV1NamespacesClients handles GET
// /admin/v1/namespaces/{namespace}/clients, requiring the `clients:read`
// scope. An absent or soft-deleted namespace is reported as
// namespace_not_found rather than an empty list.
func (s *Server) GetAdminV1NamespacesClients(w http.ResponseWriter, r *http.Request, namespace string) {
	ctx := r.Context()
	if !s.namespaceActive(ctx, w, namespace) {
		return
	}

	list, err := s.clientStore.List(ctx, namespace)
	if err != nil {
		writeInternalError(w, "cloudapi: list namespaced clients", err)
		return
	}
	resp := cloudopenapi.ClientListResponse{Clients: make([]cloudopenapi.ClientResponse, 0, len(list))}
	for _, c := range list {
		resp.Clients = append(resp.Clients, clientResponse(c))
	}
	writeCloudJSON(w, http.StatusOK, resp)
}

// GetAdminV1NamespacesClient handles GET
// /admin/v1/namespaces/{namespace}/clients/{client_id}, requiring the
// `clients:read` scope. A client_id that does not exist, is owned by a
// different namespace, or has been soft-deleted is reported identically as
// 404 client_not_found — never 403, which would confirm the id exists under
// someone else.
func (s *Server) GetAdminV1NamespacesClient(w http.ResponseWriter, r *http.Request, namespace string, clientId string) {
	ctx := r.Context()
	if !s.namespaceActive(ctx, w, namespace) {
		return
	}

	c, err := s.clientStore.Get(ctx, clientId, namespace)
	if err != nil {
		if errors.Is(err, clients.ErrClientNotFound) {
			writeCloudError(w, http.StatusNotFound, "client_not_found", "client does not exist")
			return
		}
		writeInternalError(w, "cloudapi: get namespaced client", err)
		return
	}
	writeCloudJSON(w, http.StatusOK, clientResponse(c))
}

// PutAdminV1NamespacesClient handles PUT
// /admin/v1/namespaces/{namespace}/clients/{client_id}, requiring the
// `clients:write` scope. Fields the caller omits (other than
// client_secret_hash, whose omission is preserved by
// clients.DBNamespacedClientStore's COALESCE) fall back to the client's
// CURRENT stored value, fetched here — so a caller updating only
// redirect_uris does not have to already know (or accidentally reset) the
// client's name, scope, or auth method. The same client_not_found conditions
// as GET apply, and a rejected update leaves the target row (if any, under
// its actual owner) unchanged: the store's WHERE clause (namespace_id = ...
// AND deleted_at IS NULL) makes a cross-tenant or already-deleted update
// affect zero rows rather than someone else's client.
func (s *Server) PutAdminV1NamespacesClient(w http.ResponseWriter, r *http.Request, namespace string, clientId string, params cloudopenapi.PutAdminV1NamespacesClientParams) {
	idempotencyKey := params.IdempotencyKey
	if !validIdempotencyKey(idempotencyKey) {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", "missing or invalid Idempotency-Key header")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxClientRequestBodyBytes)
	var req cloudopenapi.ClientUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", "malformed JSON request body")
		return
	}

	if len(req.RedirectUris) == 0 {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", "redirect_uris is required")
		return
	}
	if len(req.RedirectUris) > maxClientRedirectURIs {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", "redirect_uris must contain no more than 8 entries")
		return
	}
	if err := clients.ValidateRedirectURIs(req.RedirectUris); err != nil {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	secretHashHex := stringOrEmpty(req.ClientSecretHash)
	if secretHashHex != "" && !clientSecretHashPattern.MatchString(secretHashHex) {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", "client_secret_hash must be 64 lowercase hex characters")
		return
	}
	var explicitAuthMethod string
	if req.TokenEndpointAuthMethod != nil {
		explicitAuthMethod = string(*req.TokenEndpointAuthMethod)
		if err := clients.ValidateTokenEndpointAuthMethod(explicitAuthMethod); err != nil {
			writeCloudError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
	}

	ctx := r.Context()
	reqHash, err := hashClientUpdateRequest(namespace, clientId, req)
	if err != nil {
		writeInternalError(w, "cloudapi: hash client update request", err)
		return
	}

	stored, outcome, err := s.checkIdempotency(ctx, idempotencyKey, opClientUpdate, reqHash)
	if err != nil {
		writeInternalError(w, "cloudapi: check client update idempotency", err)
		return
	}
	switch outcome {
	case idempotencyReplay:
		writeStoredResponse(w, stored)
		return
	case idempotencyConflict:
		writeCloudError(w, http.StatusConflict, "idempotency_key_reused", "Idempotency-Key was previously used with a different request body")
		return
	}

	if !s.namespaceActive(ctx, w, namespace) {
		return
	}

	existing, err := s.clientStore.Get(ctx, clientId, namespace)
	if err != nil {
		if errors.Is(err, clients.ErrClientNotFound) {
			writeCloudError(w, http.StatusNotFound, "client_not_found", "client does not exist")
			return
		}
		writeInternalError(w, "cloudapi: get namespaced client for update", err)
		return
	}

	name := existing.Name
	if req.ClientName != nil {
		name = *req.ClientName
	}
	authMethod := existing.TokenEndpointAuthMethod
	if req.TokenEndpointAuthMethod != nil {
		authMethod = explicitAuthMethod
	}
	scope := strings.Join(existing.ScopesAllowed, " ")
	if req.Scope != nil {
		scope = *req.Scope
	}
	// hasSecretHash reflects what the client will end up with: the freshly
	// submitted hash if one was sent, otherwise whatever is already stored
	// (client_secret_hash is never echoed back, so "already stored" is the
	// only way to know this without the caller resubmitting it).
	hasSecretHash := len(existing.ClientSecretHash) > 0
	if req.ClientSecretHash != nil {
		hasSecretHash = secretHashHex != ""
	}
	if msg, ok := validateAuthMethodSecretPairing(authMethod, hasSecretHash); !ok {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}

	var secretHash []byte
	if secretHashHex != "" {
		secretHash, err = hex.DecodeString(secretHashHex)
		if err != nil {
			writeInternalError(w, "cloudapi: decode client_secret_hash", err)
			return
		}
	}

	updated, err := s.clientStore.Update(ctx, clients.UpdateNamespacedClient{
		ClientID:                clientId,
		NamespaceID:             namespace,
		Name:                    name,
		RedirectURIs:            req.RedirectUris,
		ScopesAllowed:           strings.Fields(scope),
		TokenEndpointAuthMethod: authMethod,
		ClientSecretHash:        secretHash,
	})
	if err != nil {
		if errors.Is(err, clients.ErrClientNotFound) {
			writeCloudError(w, http.StatusNotFound, "client_not_found", "client does not exist")
			return
		}
		writeInternalError(w, "cloudapi: update namespaced client", err)
		return
	}

	body, err := json.Marshal(clientResponse(updated))
	if err != nil {
		writeInternalError(w, "cloudapi: marshal client response", err)
		return
	}
	s.recordOperation(ctx, idempotencyKey, opClientUpdate, reqHash, http.StatusOK, body)
	writeCloudBody(w, http.StatusOK, body)
}

// DeleteAdminV1NamespacesClient handles DELETE
// /admin/v1/namespaces/{namespace}/clients/{client_id}, requiring the
// `clients:write` scope. It ALWAYS returns 204 — including when client_id is
// absent, already deleted, or owned by a DIFFERENT namespace — because
// delete must never leak whether an id exists (namespace existence is not
// even checked: SoftDelete's WHERE clause simply matches zero rows when the
// namespace itself is absent). A cross-tenant delete attempt is silently a
// no-op against the real owner's row, never an actual deletion of someone
// else's client — clients.DBNamespacedClientStore.SoftDelete's WHERE clause
// makes that structural, not just checked.
func (s *Server) DeleteAdminV1NamespacesClient(w http.ResponseWriter, r *http.Request, namespace string, clientId string, params cloudopenapi.DeleteAdminV1NamespacesClientParams) {
	idempotencyKey := params.IdempotencyKey
	if !validIdempotencyKey(idempotencyKey) {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", "missing or invalid Idempotency-Key header")
		return
	}

	ctx := r.Context()
	// DELETE carries no request body, so (namespace, client_id) IS the
	// request's identity for idempotency purposes — mirrors
	// DeleteAdminV1Namespace's reqHash over the id path parameter. The
	// \x00 separator matters: without it, namespace "a" + client_id "bc"
	// would hash identically to namespace "ab" + client_id "c".
	reqHash := hashClientDeleteRequest(namespace, clientId)

	stored, outcome, err := s.checkIdempotency(ctx, idempotencyKey, opClientDelete, reqHash)
	if err != nil {
		writeInternalError(w, "cloudapi: check client delete idempotency", err)
		return
	}
	switch outcome {
	case idempotencyReplay:
		writeStoredResponse(w, stored)
		return
	case idempotencyConflict:
		writeCloudError(w, http.StatusConflict, "idempotency_key_reused", "Idempotency-Key was previously used with a different request")
		return
	}

	if err := s.clientStore.SoftDelete(ctx, clientId, namespace); err != nil {
		writeInternalError(w, "cloudapi: soft delete namespaced client", err)
		return
	}

	s.recordOperation(ctx, idempotencyKey, opClientDelete, reqHash, http.StatusNoContent, nil)
	writeCloudBody(w, http.StatusNoContent, nil)
}

// namespaceActive reports whether namespace exists and is not soft-deleted.
// On failure it writes the appropriate error response itself (404
// namespace_not_found, or a 500 on an unexpected store error) and returns
// false so the caller can simply `if !s.namespaceActive(...) { return }`.
func (s *Server) namespaceActive(ctx context.Context, w http.ResponseWriter, namespace string) bool {
	ns, err := s.store.GetNamespace(ctx, namespace)
	if err != nil && !errors.Is(err, ErrNamespaceNotFound) {
		writeInternalError(w, "cloudapi: get namespace", err)
		return false
	}
	if errors.Is(err, ErrNamespaceNotFound) || ns.DeletedAt != nil {
		writeCloudError(w, http.StatusNotFound, "namespace_not_found", "namespace does not exist")
		return false
	}
	return true
}

// validateAuthMethodSecretPairing enforces the invariant
// internal/oidc/auth_method.go's AuthenticateClient depends on: a NULL/empty
// token_endpoint_auth_method is treated as ClientAuthNone, and under
// ClientAuthNone the client is admitted with NO credential check at all. So
// a confidential auth method (client_secret_basic/client_secret_post) MUST
// be paired with a hash — otherwise /token would reject every request from
// that client outright — and ClientAuthNone MUST NOT be paired with a hash,
// otherwise the hash is silently dead weight: the operator believes the
// client is confidential when it in fact authenticates as fully public.
func validateAuthMethodSecretPairing(authMethod string, hasSecretHash bool) (message string, ok bool) {
	switch authMethod {
	case oidc.ClientAuthNone:
		if hasSecretHash {
			return `token_endpoint_auth_method "none" must not be paired with client_secret_hash`, false
		}
	case oidc.ClientAuthSecretBasic, oidc.ClientAuthSecretPost:
		if !hasSecretHash {
			return "token_endpoint_auth_method " + authMethod + " requires client_secret_hash", false
		}
	}
	return "", true
}

// clientResponse builds the wire ClientResponse from a domain
// NamespacedClient. It NEVER includes a secret or hash field — there is no
// ClientSecretHash field on cloudopenapi.ClientResponse at all, so an
// accidental leak here would be a compile error, not just a review miss.
func clientResponse(c clients.NamespacedClient) cloudopenapi.ClientResponse {
	var namePtr *string
	if c.Name != "" {
		namePtr = &c.Name
	}
	grantTypes := append([]string(nil), c.GrantTypes...)
	responseTypes := append([]string(nil), c.ResponseTypes...)
	scope := strings.Join(c.ScopesAllowed, " ")
	return cloudopenapi.ClientResponse{
		ClientId:                c.ClientID,
		NamespaceId:             c.NamespaceID,
		ClientName:              namePtr,
		RedirectUris:            c.RedirectURIs,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		GrantTypes:              &grantTypes,
		ResponseTypes:           &responseTypes,
		Scope:                   &scope,
		CreatedAt:               c.CreatedAt,
	}
}

// stringOrEmpty dereferences an optional string field, returning "" for nil.
func stringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// grantTypesToStrings converts the generated enum-typed slice to plain
// strings for clients.ValidateGrantTypes and persistence.
func grantTypesToStrings(in []cloudopenapi.ClientCreateRequestGrantTypes) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

// responseTypesToStrings converts the generated enum-typed slice to plain
// strings for clients.ValidateResponseTypes and persistence.
func responseTypesToStrings(in []cloudopenapi.ClientCreateRequestResponseTypes) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

// canonicalClientCreateRequest fixes field order and folds in the namespace
// path segment — which is not part of the JSON body but MUST be part of the
// idempotency hash — so two requests carrying the same logical content hash
// identically regardless of client JSON formatting, and so the SAME
// Idempotency-Key reused by two DIFFERENT namespaces never collides:
// cloud_operations' primary key is (idempotency_key, operation), not
// namespace-scoped (db/migrations/0019_cloud_namespaces.up.sql).
type canonicalClientCreateRequest struct {
	Namespace               string    `json:"namespace"`
	ClientID                string    `json:"client_id"`
	ClientName              *string   `json:"client_name,omitempty"`
	RedirectURIs            []string  `json:"redirect_uris"`
	ClientSecretHash        *string   `json:"client_secret_hash,omitempty"`
	TokenEndpointAuthMethod *string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              *[]string `json:"grant_types,omitempty"`
	ResponseTypes           *[]string `json:"response_types,omitempty"`
	Scope                   *string   `json:"scope,omitempty"`
}

// hashClientCreateRequest computes the idempotency ledger's request_hash for
// a client create request, scoped to namespace (see
// canonicalClientCreateRequest's doc comment).
func hashClientCreateRequest(namespace string, req cloudopenapi.ClientCreateRequest) ([32]byte, error) {
	canon := canonicalClientCreateRequest{
		Namespace:        namespace,
		ClientID:         req.ClientId,
		ClientName:       req.ClientName,
		RedirectURIs:     req.RedirectUris,
		ClientSecretHash: req.ClientSecretHash,
		Scope:            req.Scope,
	}
	if req.TokenEndpointAuthMethod != nil {
		v := string(*req.TokenEndpointAuthMethod)
		canon.TokenEndpointAuthMethod = &v
	}
	if req.GrantTypes != nil {
		v := grantTypesToStrings(*req.GrantTypes)
		canon.GrantTypes = &v
	}
	if req.ResponseTypes != nil {
		v := responseTypesToStrings(*req.ResponseTypes)
		canon.ResponseTypes = &v
	}
	data, err := json.Marshal(canon)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}

// canonicalClientUpdateRequest is hashClientCreateRequest's counterpart for
// PUT — see canonicalClientCreateRequest's doc comment for why namespace and
// client_id (here the path parameter, not a body field) are folded in.
type canonicalClientUpdateRequest struct {
	Namespace               string   `json:"namespace"`
	ClientID                string   `json:"client_id"`
	ClientName              *string  `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientSecretHash        *string  `json:"client_secret_hash,omitempty"`
	TokenEndpointAuthMethod *string  `json:"token_endpoint_auth_method,omitempty"`
	Scope                   *string  `json:"scope,omitempty"`
}

// hashClientUpdateRequest computes the idempotency ledger's request_hash for
// a client update request.
func hashClientUpdateRequest(namespace, clientID string, req cloudopenapi.ClientUpdateRequest) ([32]byte, error) {
	canon := canonicalClientUpdateRequest{
		Namespace:        namespace,
		ClientID:         clientID,
		ClientName:       req.ClientName,
		RedirectURIs:     req.RedirectUris,
		ClientSecretHash: req.ClientSecretHash,
		Scope:            req.Scope,
	}
	if req.TokenEndpointAuthMethod != nil {
		v := string(*req.TokenEndpointAuthMethod)
		canon.TokenEndpointAuthMethod = &v
	}
	data, err := json.Marshal(canon)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}

// hashClientDeleteRequest computes the idempotency ledger's request_hash for
// a client delete request. DELETE has no body, so (namespace, clientID) IS
// the request's identity. The \x00 separator is load-bearing: without it,
// namespace "a" + clientID "bc" would hash identically to namespace "ab" +
// clientID "c".
func hashClientDeleteRequest(namespace, clientID string) [32]byte {
	return sha256.Sum256([]byte(namespace + "\x00" + clientID))
}
