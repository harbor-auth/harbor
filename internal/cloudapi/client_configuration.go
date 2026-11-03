package cloudapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/harbor-auth/harbor/internal/clients"
	cloudopenapi "github.com/harbor-auth/harbor/internal/gen/openapi/cloud"
)

type clientConfigurationRequest struct {
	ClientID      string    `json:"client_id"`
	Generation    *int64    `json:"generation"`
	ClientName    *string   `json:"client_name"`
	RedirectURIs  []string  `json:"redirect_uris"`
	SecretHash    *string   `json:"client_secret_hash"`
	AuthMethod    *string   `json:"token_endpoint_auth_method"`
	GrantTypes    *[]string `json:"grant_types"`
	ResponseTypes *[]string `json:"response_types"`
	Scope         *string   `json:"scope"`
}

func (s *Server) PutAdminV1NamespacesClientConfiguration(w http.ResponseWriter, r *http.Request, namespace, clientID string, params cloudopenapi.PutAdminV1NamespacesClientConfigurationParams) {
	s.serveClientMutation(w, r, namespace, clientID, "upsert", params.IdempotencyKey)
}
func (s *Server) DeleteAdminV1NamespacesClientConfiguration(w http.ResponseWriter, r *http.Request, namespace, clientID string, params cloudopenapi.DeleteAdminV1NamespacesClientConfigurationParams) {
	s.serveClientMutation(w, r, namespace, clientID, "delete", params.IdempotencyKey)
}

func (s *Server) serveClientMutation(w http.ResponseWriter, r *http.Request, namespace, clientID, action, idempotencyKey string) {
	if !namespacePermitted(r.Context(), w, namespace) {
		return
	}
	if !validIdempotencyKey(idempotencyKey) {
		writeCloudError(w, 400, "invalid_request", "missing or invalid Idempotency-Key header")
		return
	}
	if !namespaceIDPattern.MatchString(namespace) {
		writeCloudError(w, 400, "invalid_request", "invalid namespace")
		return
	}
	var req clientConfigurationRequest
	var generation int64
	if action == "delete" {
		values, ok := r.URL.Query()["generation"]
		if !ok || len(values) != 1 {
			writeCloudError(w, 400, "invalid_request", "one positive generation is required")
			return
		}
		var err error
		generation, err = strconv.ParseInt(values[0], 10, 64)
		if err != nil || generation <= 0 {
			writeCloudError(w, 400, "invalid_request", "positive generation is required")
			return
		}
	} else {
		r.Body = http.MaxBytesReader(w, r.Body, maxClientRequestBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeCloudError(w, 400, "invalid_request", "malformed JSON request body")
			return
		}
		if req.Generation == nil || *req.Generation <= 0 {
			writeCloudError(w, 400, "invalid_request", "positive generation is required")
			return
		}
		generation = *req.Generation
		if action == "create" {
			clientID = req.ClientID
		} else if req.ClientID != "" && req.ClientID != clientID {
			writeCloudError(w, 400, "invalid_request", "client_id does not match path")
			return
		}
	}
	if !clientIDPattern.MatchString(clientID) {
		writeCloudError(w, 400, "invalid_request", "invalid client_id")
		return
	}
	var desired clients.ClientConfiguration
	var expectedBase *int64
	if action != "delete" {
		if len(req.RedirectURIs) > maxClientRedirectURIs {
			writeCloudError(w, 400, "invalid_request", "redirect_uris must contain no more than 8 entries")
			return
		}
		if err := clients.ValidateRedirectURIs(req.RedirectURIs); err != nil {
			writeCloudError(w, 400, "invalid_request", err.Error())
			return
		}
		// Legacy PUT remains a partial metadata operation, but the SQL mutation
		// receives one full snapshot and still enforces the same generation fence.
		if action == "update" {
			existing, err := s.clientStore.Get(r.Context(), clientID, namespace)
			if errors.Is(err, clients.ErrClientNotFound) {
				writeCloudError(w, 404, "client_not_found", "client does not exist")
				return
			}
			if err != nil {
				writeInternalError(w, "cloudapi: read client configuration", err)
				return
			}
			base := existing.Generation
			expectedBase = &base
			if req.ClientName == nil {
				req.ClientName = &existing.Name
			}
			if req.AuthMethod == nil {
				req.AuthMethod = &existing.TokenEndpointAuthMethod
			}
			if req.Scope == nil {
				value := strings.Join(existing.ScopesAllowed, " ")
				req.Scope = &value
			}
			if req.SecretHash == nil && len(existing.ClientSecretHash) > 0 {
				value := hex.EncodeToString(existing.ClientSecretHash)
				req.SecretHash = &value
			}
			if req.GrantTypes == nil {
				req.GrantTypes = &existing.GrantTypes
			}
			if req.ResponseTypes == nil {
				req.ResponseTypes = &existing.ResponseTypes
			}
		}
		method := defaultClientAuthMethod
		if req.AuthMethod != nil {
			var ok bool
			method, ok = resolveExplicitAuthMethod(w, *req.AuthMethod)
			if !ok {
				return
			}
		}
		hash := stringOrEmpty(req.SecretHash)
		if req.SecretHash != nil && !clientSecretHashPattern.MatchString(hash) {
			writeCloudError(w, 400, "invalid_request", "client_secret_hash must be 64 lowercase hex characters")
			return
		}
		if msg, ok := validateAuthMethodSecretPairing(method, hash != ""); !ok {
			writeCloudError(w, 400, "invalid_request", msg)
			return
		}
		grants := defaultClientGrantTypes
		if req.GrantTypes != nil {
			grants = *req.GrantTypes
		}
		responses := defaultClientResponseTypes
		if req.ResponseTypes != nil {
			responses = *req.ResponseTypes
		}
		if err := clients.ValidateGrantTypes(grants); err != nil {
			writeCloudError(w, 400, "invalid_request", err.Error())
			return
		}
		if err := clients.ValidateResponseTypes(responses); err != nil {
			writeCloudError(w, 400, "invalid_request", err.Error())
			return
		}
		scope := defaultClientScope
		if req.Scope != nil {
			scope = *req.Scope
		}
		desired = clients.ClientConfiguration{Name: stringOrEmpty(req.ClientName), RedirectURIs: req.RedirectURIs,
			ScopesAllowed: strings.Fields(scope), SecretHash: hash, GrantTypes: grants, ResponseTypes: responses, AuthMethod: method}
		if !s.namespaceActive(r.Context(), w, namespace) {
			return
		}
	}
	// Idempotency conflicts are checked before mutation, but a cached response
	// never bypasses the generation fence: even identical ledger retries call SQL.
	identity, _ := json.Marshal(struct {
		Namespace, Client string
		Generation        int64
		Desired           clients.ClientConfiguration
		Deleted           bool
	}{namespace, clientID, generation, desired, action == "delete"})
	reqHash := sha256.Sum256(identity)
	operation := opClientUpdate
	if action == "create" {
		operation = opClientCreate
	} else if action == "delete" {
		operation = opClientDelete
	}
	_, outcome, ledgerErr := s.checkIdempotency(r.Context(), idempotencyKey, operation, reqHash)
	if ledgerErr != nil {
		writeInternalError(w, "cloudapi: read client mutation ledger", ledgerErr)
		return
	}
	if outcome == idempotencyConflict {
		writeCloudError(w, 409, "idempotency_key_reused", "Idempotency-Key was previously used with a different request")
		return
	}
	applied, err := s.clientStore.ApplyVersioned(r.Context(), clients.VersionedClientMutation{
		Action: action, NamespaceID: namespace, ClientID: clientID, Generation: generation, Configuration: desired, ExpectedBase: expectedBase,
	})
	if err != nil {
		switch {
		case errors.Is(err, clients.ErrStaleClientGeneration):
			writeCloudError(w, 409, "stale_generation", "a newer generation is already accepted")
		case errors.Is(err, clients.ErrClientGenerationConflict):
			writeCloudError(w, 409, "generation_conflict", "generation conflicts with accepted state or terminal deletion")
		case errors.Is(err, clients.ErrNamespacedClientExists):
			writeCloudError(w, 409, "client_already_exists", "a client with this id already exists")
		case errors.Is(err, clients.ErrClientNotFound):
			writeCloudError(w, 404, "client_not_found", "client does not exist")
		case errors.Is(err, clients.ErrNamespaceInactive):
			writeCloudError(w, 404, "namespace_not_found", "namespace does not exist")
		default:
			writeInternalError(w, "cloudapi: apply client configuration", err)
		}
		return
	}
	if action == "delete" {
		w.Header().Set("X-Harbor-Generation", strconv.FormatInt(generation, 10))
		s.recordOperation(r.Context(), idempotencyKey, operation, reqHash, http.StatusNoContent, nil)
		writeCloudBody(w, http.StatusNoContent, nil)
		return
	}
	status := http.StatusOK
	if action == "create" {
		status = http.StatusCreated
	}
	body, marshalErr := json.Marshal(clientResponse(applied))
	if marshalErr != nil {
		writeInternalError(w, "cloudapi: encode client configuration", marshalErr)
		return
	}
	w.Header().Set("X-Harbor-Generation", strconv.FormatInt(generation, 10))
	s.recordOperation(r.Context(), idempotencyKey, operation, reqHash, status, body)
	writeCloudBody(w, status, body)
}
