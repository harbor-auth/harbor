// namespaces.go implements the namespace-lifecycle operations of
// cloudopenapi.ServerInterface (internal/gen/openapi/cloud, generated from
// api/openapi/harbor-cloud.yaml): POST/GET/DELETE /admin/v1/namespaces[/{id}].
// Session minting (sessions.go) and key rotation (keys.go) add their
// ServerInterface methods to *Server in sibling files of a later task.
package cloudapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/harbor-auth/harbor/internal/clients"
	cloudopenapi "github.com/harbor-auth/harbor/internal/gen/openapi/cloud"
)

// ClientProvisioningStore is the narrow behaviour clients.go's five handlers
// need from a namespace-scoped OIDC client store. Depending on the interface
// (not clients.DBNamespacedClientStore directly) keeps this package testable
// with a fake and mirrors mgmtapi.ClientRegistrationStore's seam.
type ClientProvisioningStore interface {
	Create(ctx context.Context, c clients.NewNamespacedClient) (clients.NamespacedClient, error)
	Get(ctx context.Context, clientID, namespaceID string) (clients.NamespacedClient, error)
	List(ctx context.Context, namespaceID string) ([]clients.NamespacedClient, error)
	Update(ctx context.Context, c clients.UpdateNamespacedClient) (clients.NamespacedClient, error)
	SoftDelete(ctx context.Context, clientID, namespaceID string) error
}

// maxNamespaceRequestBodyBytes caps the namespace create request body (an id
// and an optional display name — a tiny JSON object), preventing a flooded
// private endpoint from exhausting memory (mirrors mgmtapi's
// maxRegisterBody/oidcapi's maxRotateBodyBytes).
const maxNamespaceRequestBodyBytes = 16 * 1024

// Idempotency-ledger operation names (cloud_operations.operation), matching
// the examples in db/migrations/0019_cloud_namespaces.up.sql.
const (
	opNamespaceCreate = "namespace.create"
	opNamespaceDelete = "namespace.delete"
)

// namespaceIDPattern matches NamespaceCreateRequest.id's documented pattern
// in api/openapi/harbor-cloud.yaml: lowercase alphanumeric and hyphens,
// starting and ending with an alphanumeric.
var namespaceIDPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// maxIdempotencyKeyLength mirrors the IdempotencyKey parameter's maxLength in
// api/openapi/harbor-cloud.yaml.
const maxIdempotencyKeyLength = 255

// Server implements the cloudopenapi.ServerInterface operations backed by a
// *Store and a ClientProvisioningStore. It holds no auth state itself —
// service-JWT verification (serviceauth.go) runs as HTTP middleware ahead of
// these handlers, wired in a later task.
type Server struct {
	store       *Store
	clientStore ClientProvisioningStore
}

// NewServer wraps a *Store and a ClientProvisioningStore. Panics if either is
// nil — callers must ensure the server is wired before startup (mirrors
// NewStore's nil-querier panic).
func NewServer(store *Store, clientStore ClientProvisioningStore) *Server {
	if store == nil {
		panic("cloudapi: nil store")
	}
	if clientStore == nil {
		panic("cloudapi: nil client store")
	}
	return &Server{store: store, clientStore: clientStore}
}

// storedResponse is the JSON envelope persisted in
// cloud_operations.response_body: the exact status code and body a replayed
// Idempotency-Key must reproduce verbatim (db/migrations/0019_cloud_namespaces.up.sql).
type storedResponse struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body,omitempty"`
}

// idempotencyOutcome is the result of consulting the cloud_operations ledger
// for a given (Idempotency-Key, operation) pair.
type idempotencyOutcome int

const (
	// idempotencyProceed means no ledger entry exists yet; the handler should
	// perform the operation and record it.
	idempotencyProceed idempotencyOutcome = iota
	// idempotencyReplay means a ledger entry exists with a matching request
	// hash; the handler must return the stored response verbatim.
	idempotencyReplay
	// idempotencyConflict means a ledger entry exists with a DIFFERENT request
	// hash; the handler must reject with 409 idempotency_key_reused.
	idempotencyConflict
)

// checkIdempotency looks up the (key, operation) pair in the cloud_operations
// ledger and reports what the caller should do next. A store error other
// than ErrOperationNotFound is returned as-is (the caller maps it to a 500).
func (s *Server) checkIdempotency(ctx context.Context, key, operation string, reqHash [32]byte) (storedResponse, idempotencyOutcome, error) {
	op, err := s.store.GetOperation(ctx, key, operation)
	if errors.Is(err, ErrOperationNotFound) {
		return storedResponse{}, idempotencyProceed, nil
	}
	if err != nil {
		return storedResponse{}, idempotencyProceed, err
	}
	if !bytes.Equal(op.RequestHash, reqHash[:]) {
		return storedResponse{}, idempotencyConflict, nil
	}
	var stored storedResponse
	if err := json.Unmarshal(op.ResponseBody, &stored); err != nil {
		return storedResponse{}, idempotencyProceed, fmt.Errorf("cloudapi: decode stored operation response: %w", err)
	}
	return stored, idempotencyReplay, nil
}

// recordOperation persists the (key, operation) ledger entry so a later
// replay can reproduce this exact response. A failure to record is logged
// but never fails the request: the underlying create/delete already
// succeeded, and refusing to respond would just make a well-formed request
// look like it failed. ErrOperationAlreadyExists (a concurrent duplicate
// write) is not an error worth logging — the ledger already has a row for
// this pair.
func (s *Server) recordOperation(ctx context.Context, key, operation string, reqHash [32]byte, status int, body []byte) {
	envelope, err := json.Marshal(storedResponse{Status: status, Body: json.RawMessage(body)})
	if err != nil {
		slog.Default().Error("cloudapi: marshal idempotency envelope", "operation", operation, "error", err)
		return
	}
	if _, err := s.store.CreateOperation(ctx, key, operation, reqHash[:], envelope); err != nil && !errors.Is(err, ErrOperationAlreadyExists) {
		slog.Default().Warn("cloudapi: record idempotency ledger entry", "operation", operation, "error", err)
	}
}

// PostAdminV1Namespaces handles POST /admin/v1/namespaces (namespace
// create), requiring the `namespaces:write` scope (enforced by the auth
// middleware ahead of this handler). It is idempotent on Idempotency-Key: a
// retry with the same key and the same request body returns the original
// response verbatim; the same key with a different body is rejected with
// 409 idempotency_key_reused; a fresh key naming an already-active namespace
// is rejected with 409 namespace_already_exists.
func (s *Server) PostAdminV1Namespaces(w http.ResponseWriter, r *http.Request, params cloudopenapi.PostAdminV1NamespacesParams) {
	idempotencyKey := params.IdempotencyKey
	if !validIdempotencyKey(idempotencyKey) {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", "missing or invalid Idempotency-Key header")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxNamespaceRequestBodyBytes)
	var req cloudopenapi.NamespaceCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", "malformed JSON request body")
		return
	}
	if !namespaceIDPattern.MatchString(req.Id) {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", "id must be lowercase alphanumeric and hyphens")
		return
	}

	ctx := r.Context()
	reqHash, err := hashNamespaceCreateRequest(req)
	if err != nil {
		writeInternalError(w, "cloudapi: hash namespace create request", err)
		return
	}

	stored, outcome, err := s.checkIdempotency(ctx, idempotencyKey, opNamespaceCreate, reqHash)
	if err != nil {
		writeInternalError(w, "cloudapi: check namespace create idempotency", err)
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

	// cloud_namespaces.id is caller-supplied and unique (primary key), so a
	// fresh Idempotency-Key naming an existing, active-or-deleted id fails
	// here with ErrNamespaceAlreadyExists — mapped to 409
	// namespace_already_exists, distinct from the idempotency-key conflict
	// above.
	ns, err := s.store.CreateNamespace(ctx, req.Id, string(cloudopenapi.Active))
	if err != nil {
		if errors.Is(err, ErrNamespaceAlreadyExists) {
			writeCloudError(w, http.StatusConflict, "namespace_already_exists", "a namespace with this id already exists")
			return
		}
		writeInternalError(w, "cloudapi: create namespace", err)
		return
	}

	// display_name has no column in cloud_namespaces (it is "never used for
	// lookups or auth" per api/openapi/harbor-cloud.yaml) — it is echoed back
	// in this create response from the request, not persisted, so a later
	// GET never returns it.
	resp := namespaceResponse(ns, req.DisplayName)
	body, err := json.Marshal(resp)
	if err != nil {
		writeInternalError(w, "cloudapi: marshal namespace response", err)
		return
	}
	s.recordOperation(ctx, idempotencyKey, opNamespaceCreate, reqHash, http.StatusCreated, body)
	writeCloudBody(w, http.StatusCreated, body)
}

// GetAdminV1Namespace handles GET /admin/v1/namespaces/{id}, requiring the
// `namespaces:read` scope. A namespace that does not exist, or that has been
// soft-deleted, returns 404 namespace_not_found — deletion is never
// distinguishable from absence on this route.
func (s *Server) GetAdminV1Namespace(w http.ResponseWriter, r *http.Request, id string) {
	ns, err := s.store.GetNamespace(r.Context(), id)
	if errors.Is(err, ErrNamespaceNotFound) {
		writeCloudError(w, http.StatusNotFound, "namespace_not_found", "namespace does not exist")
		return
	}
	if err != nil {
		writeInternalError(w, "cloudapi: get namespace", err)
		return
	}
	if ns.DeletedAt != nil {
		writeCloudError(w, http.StatusNotFound, "namespace_not_found", "namespace does not exist")
		return
	}
	writeCloudJSON(w, http.StatusOK, namespaceResponse(ns, nil))
}

// DeleteAdminV1Namespace handles DELETE /admin/v1/namespaces/{id}, requiring
// the `namespaces:write` scope. It soft-deletes the namespace and ALWAYS
// returns 204 — including when id is absent or already deleted — because
// delete is naturally idempotent (api/openapi/harbor-cloud.yaml). An
// Idempotency-Key is still required and honored the same way as create: a
// reused key targeting a different id is rejected with
// 409 idempotency_key_reused.
func (s *Server) DeleteAdminV1Namespace(w http.ResponseWriter, r *http.Request, id string, params cloudopenapi.DeleteAdminV1NamespaceParams) {
	idempotencyKey := params.IdempotencyKey
	if !validIdempotencyKey(idempotencyKey) {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", "missing or invalid Idempotency-Key header")
		return
	}

	ctx := r.Context()
	// DELETE carries no request body, so the id path parameter IS the
	// request's identity for idempotency purposes: reusing the key against a
	// different id is a "different body" exactly as create's spec describes.
	reqHash := sha256.Sum256([]byte(id))

	stored, outcome, err := s.checkIdempotency(ctx, idempotencyKey, opNamespaceDelete, reqHash)
	if err != nil {
		writeInternalError(w, "cloudapi: check namespace delete idempotency", err)
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

	if err := s.store.SoftDeleteNamespace(ctx, id); err != nil {
		writeInternalError(w, "cloudapi: soft delete namespace", err)
		return
	}

	s.recordOperation(ctx, idempotencyKey, opNamespaceDelete, reqHash, http.StatusNoContent, nil)
	writeCloudBody(w, http.StatusNoContent, nil)
}

// validIdempotencyKey reports whether key satisfies the IdempotencyKey
// parameter's documented bounds (minLength 1, maxLength 255) in
// api/openapi/harbor-cloud.yaml. The generated ServerInterfaceWrapper only
// checks the header is present, not its length, so the handler enforces
// these bounds itself.
func validIdempotencyKey(key string) bool {
	return key != "" && len(key) <= maxIdempotencyKeyLength
}

// canonicalNamespaceCreateRequest fixes field order and omits an absent
// display_name so two requests carrying the same logical content hash
// identically regardless of client JSON formatting.
type canonicalNamespaceCreateRequest struct {
	ID          string  `json:"id"`
	DisplayName *string `json:"display_name,omitempty"`
}

// hashNamespaceCreateRequest computes the idempotency ledger's request_hash
// for a namespace create request.
func hashNamespaceCreateRequest(req cloudopenapi.NamespaceCreateRequest) ([32]byte, error) {
	canon, err := json.Marshal(canonicalNamespaceCreateRequest{ID: req.Id, DisplayName: req.DisplayName})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canon), nil
}

// namespaceResponse builds the wire NamespaceResponse from a domain
// Namespace. displayName is only ever non-nil on the create response (see
// PostAdminV1Namespaces) since it is not persisted.
func namespaceResponse(ns Namespace, displayName *string) cloudopenapi.NamespaceResponse {
	return cloudopenapi.NamespaceResponse{
		Id:          ns.ID,
		Status:      cloudopenapi.NamespaceResponseStatus(ns.Status),
		DisplayName: displayName,
		CreatedAt:   ns.CreatedAt,
		UpdatedAt:   ns.UpdatedAt,
		DeletedAt:   ns.DeletedAt,
	}
}

// writeCloudBody writes status with body written verbatim (already-marshaled
// JSON), or no body at all when body is empty/absent (e.g. a 204 with no
// content, or a replayed response whose original body was empty).
func writeCloudBody(w http.ResponseWriter, status int, body []byte) {
	if len(body) == 0 || string(body) == "null" {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		slog.Default().Warn("cloudapi: failed to write response body", "error", err)
	}
}

// writeStoredResponse replays a ledger-stored response verbatim, including
// its original status code.
func writeStoredResponse(w http.ResponseWriter, stored storedResponse) {
	writeCloudBody(w, stored.Status, stored.Body)
}

// writeCloudJSON marshals v and writes it as the response body.
func writeCloudJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		slog.Default().Error("cloudapi: marshal response", "error", err)
		writeCloudBody(w, http.StatusInternalServerError, nil)
		return
	}
	writeCloudBody(w, status, body)
}

// writeCloudError renders the generated Error envelope as JSON
// (api/openapi/harbor-cloud.yaml `Error` schema). Messages must carry no PII
// or token material.
func writeCloudError(w http.ResponseWriter, status int, code, message string) {
	writeCloudJSON(w, status, cloudopenapi.Error{Code: cloudopenapi.ErrorCode(code), Message: message})
}

// writeInternalError logs the internal error detail (server-side only) and
// writes a generic, detail-free 500 to the caller.
func writeInternalError(w http.ResponseWriter, context string, err error) {
	slog.Default().Error(context, "error", err)
	writeCloudError(w, http.StatusInternalServerError, "internal_error", "internal server error")
}
