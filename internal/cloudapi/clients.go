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
	"encoding/binary"
	"errors"
	"net/http"
	"regexp"
	"strings"

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
)

// PostAdminV1NamespacesClients is the legacy create route. A positive
// generation is mandatory and the same SQL fence as /configuration applies.
func (s *Server) PostAdminV1NamespacesClients(w http.ResponseWriter, r *http.Request, namespace string, params cloudopenapi.PostAdminV1NamespacesClientsParams) {
	s.serveClientMutation(w, r, namespace, "", "create", params.IdempotencyKey)
}

// GetAdminV1NamespacesClients handles GET
// /admin/v1/namespaces/{namespace}/clients, requiring the `clients:read`
// scope. An absent or soft-deleted namespace is reported as
// namespace_not_found rather than an empty list.
func (s *Server) GetAdminV1NamespacesClients(w http.ResponseWriter, r *http.Request, namespace string) {
	ctx := r.Context()
	if !namespacePermitted(ctx, w, namespace) {
		return
	}
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
	if !namespacePermitted(ctx, w, namespace) {
		return
	}
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

// PutAdminV1NamespacesClient retains partial-update syntax, with mandatory
// generation fencing and an atomic expected-base guard against lost updates.
func (s *Server) PutAdminV1NamespacesClient(w http.ResponseWriter, r *http.Request, namespace string, clientId string, params cloudopenapi.PutAdminV1NamespacesClientParams) {
	s.serveClientMutation(w, r, namespace, clientId, "update", params.IdempotencyKey)
}

// DeleteAdminV1NamespacesClient requires a positive generation query value.
// Successful terminal deletion returns 204; stale/conflicting generations fail.
func (s *Server) DeleteAdminV1NamespacesClient(w http.ResponseWriter, r *http.Request, namespace string, clientId string, params cloudopenapi.DeleteAdminV1NamespacesClientParams) {
	s.serveClientMutation(w, r, namespace, clientId, "delete", params.IdempotencyKey)
}

// namespacePermitted enforces the M5 per-anchor namespace binding: it reports
// whether the trust anchor that signed the caller's bearer token is permitted
// to act on namespace, writing 403 cross_tenant_forbidden itself and returning
// false when it is not — so a caller can simply
// `if !namespacePermitted(ctx, w, ns) { return }`.
//
// Scope alone cannot express this boundary: two tenants legitimately hold the
// same clients:write scope, and the namespace is the only thing separating
// them. Without this check the `ns=` restriction in
// CLOUD_SERVICE_AUTH_PUBLIC_KEYS would bind only POST /admin/v1/user-sessions,
// and one tenant's bridge key could read, create, repoint, or delete every
// other tenant's OIDC clients just by naming their namespace in the path.
//
// It lives in the handler rather than the route wiring deliberately: the
// binding is a property of the operation, so a handler cannot later be
// re-wired or re-mounted and silently lose it. Call it BEFORE any store
// lookup, so an anchor restricted away from a namespace cannot use the
// handler's own 404 as an existence oracle.
//
// ok=false from ServiceClaimsFromContext means the handler was invoked
// directly, bypassing the auth middleware that attaches the claims (a unit
// test in isolation): there is no anchor to bind to, so the call is treated as
// unrestricted — the same convention PostUserSessions already uses.
func namespacePermitted(ctx context.Context, w http.ResponseWriter, namespace string) bool {
	if claims, ok := ServiceClaimsFromContext(ctx); ok && !claims.NamespacePermitted(namespace) {
		writeCloudError(w, http.StatusForbidden, string(cloudopenapi.ErrorCodeCrossTenantForbidden),
			"this signing key is not permitted to act on the requested namespace")
		return false
	}
	return true
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

// resolveExplicitAuthMethod validates a token_endpoint_auth_method the caller
// explicitly supplied (as opposed to omitted the field, which the caller
// defaults away from this function entirely). raw == "" is rejected outright
// rather than treated as "caller omitted it": ClientCreateRequestTokenEndpointAuthMethod
// / ClientUpdateRequestTokenEndpointAuthMethod (internal/gen/openapi/cloud) are
// bare `string` types, so oapi-codegen does NOT enforce the OpenAPI enum at
// decode time, and {"token_endpoint_auth_method":""} decodes into a non-nil
// pointer to "". Without this check that "" would reach
// clients.ValidateTokenEndpointAuthMethod, which treats "" as "field omitted,
// apply the default" for mgmtapi's RFC 7591 registerRequest (a bare string,
// with no way to distinguish omitted from explicit empty) — and from there
// into a NULL token_endpoint_auth_method column, which
// internal/oidc/auth_method.go maps to ClientAuthNone: a live confidential
// client silently downgraded to authenticating with NO credential (H1).
func resolveExplicitAuthMethod(w http.ResponseWriter, raw string) (string, bool) {
	if raw == "" {
		writeCloudError(w, http.StatusBadRequest, "invalid_request",
			`token_endpoint_auth_method, if present, must be exactly one of "client_secret_basic", "client_secret_post", "none" — omit the field entirely to accept the default`)
		return "", false
	}
	if err := clients.ValidateTokenEndpointAuthMethod(raw); err != nil {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return "", false
	}
	return raw, true
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
	default:
		// Fail closed. This is the second, independent line of defense
		// against H1: resolveExplicitAuthMethod should already have rejected
		// anything other than the three known enum values (including "") by
		// the time this runs, but this switch must never silently fall
		// through and return ok=true for an unrecognized authMethod — that
		// is exactly how "" (matching no case above) once slipped past this
		// function entirely.
		return "token_endpoint_auth_method " + authMethod + " is not a recognized value", false
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
	// []string{} (not []string(nil)) as the append base: an empty
	// grant_types/response_types must marshal as JSON "[]", not "null" —
	// append onto a nil slice stays nil when c.GrantTypes/c.ResponseTypes is
	// itself empty, and json.Marshal renders a nil slice through a non-nil
	// *[]string pointer as "null".
	grantTypes := append([]string{}, c.GrantTypes...)
	responseTypes := append([]string{}, c.ResponseTypes...)
	scope := strings.Join(c.ScopesAllowed, " ")
	return cloudopenapi.ClientResponse{
		Generation:              c.Generation,
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

// hashClientDeleteRequest computes the idempotency ledger's request_hash for
// a client delete request. DELETE has no body, so (namespace, clientID) IS
// the request's identity, and the encoding below must be injective: a single
// separator byte is NOT sufficient — namespace `"a\x00"` + clientID `"b"` and
// namespace `"a"` + clientID `"\x00b"` would both encode to the literal bytes
// `a\x00\x00b` (L2). This mirrors internal/identity/ppid.go's encodeMessage:
// length-prefix namespace with a fixed 8-byte big-endian length before
// appending clientID, so no two distinct (namespace, clientID) pairs can ever
// produce the same message regardless of what bytes either string contains.
func hashClientDeleteRequest(namespace, clientID string) [32]byte {
	ns := []byte(namespace)
	id := []byte(clientID)
	msg := make([]byte, 0, 8+len(ns)+len(id))
	var lenPrefix [8]byte
	binary.BigEndian.PutUint64(lenPrefix[:], uint64(len(ns)))
	msg = append(msg, lenPrefix[:]...)
	msg = append(msg, ns...)
	msg = append(msg, id...)
	return sha256.Sum256(msg)
}
