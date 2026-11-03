package clients

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/harbor-auth/harbor/internal/gen/db"
)

var (
	ErrStaleClientGeneration     = errors.New("clients: stale generation")
	ErrClientGenerationConflict  = errors.New("clients: generation conflict")
	ErrClientIdempotencyConflict = errors.New("clients: idempotency key reused")
	ErrClientOperationInProgress = errors.New("clients: operation in progress")
)

// ClientConfiguration is a full desired snapshot. The same representation is
// hashed for create/update/upsert, so HTTP method and retry path cannot change
// mutation identity. Hashes, never plaintext credentials, cross this boundary.
type ClientConfiguration struct {
	Name          string   `json:"name"`
	RedirectURIs  []string `json:"redirect_uris"`
	ScopesAllowed []string `json:"scopes_allowed"`
	SecretHash    string   `json:"client_secret_hash"`
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	AuthMethod    string   `json:"token_endpoint_auth_method"`
}

// ClientMutationIdempotency binds a successful remote write to its durable key.
// The request hash includes generation; unlike the generation hash it identifies
// the exact operation rather than only the desired configuration.
type ClientMutationIdempotency struct {
	Key         string
	Operation   string
	RequestHash [32]byte
}

type VersionedClientMutation struct {
	Idempotency   *ClientMutationIdempotency
	Action        string
	NamespaceID   string
	ClientID      string
	Generation    int64
	ExpectedBase  *int64
	Configuration ClientConfiguration
}

type versionedClientQuerier interface {
	ApplyCloudClientMutation(context.Context, db.ApplyCloudClientMutationParams) ([]byte, error)
}

type versionedClientOperationQuerier interface {
	ApplyCloudClientOperation(context.Context, db.ApplyCloudClientOperationParams) ([]byte, error)
}

// ApplyVersioned performs all generation decisions and writes atomically in
// PostgreSQL. A cached idempotency ledger response is never an authorization to
// replace or acknowledge a newer generation.
func (s *DBNamespacedClientStore) ApplyVersioned(ctx context.Context, m VersionedClientMutation) (NamespacedClient, error) {
	if m.Generation <= 0 {
		return NamespacedClient{}, ErrClientGenerationConflict
	}
	q, ok := s.q.(versionedClientQuerier)
	if !ok {
		return NamespacedClient{}, errors.New("clients: versioned mutation querier unavailable")
	}
	config, err := json.Marshal(struct {
		ClientConfiguration
		ExpectedBase *int64 `json:"_expected_generation,omitempty"`
	}{m.Configuration, m.ExpectedBase})
	if err != nil {
		return NamespacedClient{}, err
	}
	identity := struct {
		NamespaceID   string               `json:"namespace_id"`
		ClientID      string               `json:"client_id"`
		Deleted       bool                 `json:"deleted"`
		Configuration *ClientConfiguration `json:"configuration,omitempty"`
	}{NamespaceID: m.NamespaceID, ClientID: m.ClientID, Deleted: m.Action == "delete"}
	if m.Action != "delete" {
		identity.Configuration = &m.Configuration
	}
	canonical, err := json.Marshal(identity)
	if err != nil {
		return NamespacedClient{}, err
	}
	hash := sha256.Sum256(canonical)
	var raw []byte
	if m.Idempotency != nil {
		operationQuerier, ok := s.q.(versionedClientOperationQuerier)
		if !ok {
			return NamespacedClient{}, errors.New("clients: atomic operation querier unavailable")
		}
		raw, err = operationQuerier.ApplyCloudClientOperation(ctx, db.ApplyCloudClientOperationParams{
			Action: m.Action, NamespaceID: m.NamespaceID, ClientID: m.ClientID, Generation: m.Generation, RequestHash: hash[:], Config: config,
			IdempotencyKey: m.Idempotency.Key, Operation: m.Idempotency.Operation, OperationHash: m.Idempotency.RequestHash[:],
		})
	} else {
		raw, err = q.ApplyCloudClientMutation(ctx, db.ApplyCloudClientMutationParams{
			Action: m.Action, NamespaceID: m.NamespaceID, ClientID: m.ClientID, Generation: m.Generation, RequestHash: hash[:], Config: config,
		})
	}
	if err != nil {
		return NamespacedClient{}, fmt.Errorf("clients: apply fenced mutation: %w", err)
	}
	var result struct {
		Outcome string           `json:"outcome"`
		Client  *db.RelyingParty `json:"client"`
	}
	if err = json.Unmarshal(raw, &result); err != nil {
		return NamespacedClient{}, fmt.Errorf("clients: decode fenced mutation: %w", err)
	}
	switch result.Outcome {
	case "applied", "replayed":
		if m.Action == "delete" {
			return NamespacedClient{ClientID: m.ClientID, NamespaceID: m.NamespaceID, Generation: m.Generation}, nil
		}
		if result.Client == nil {
			return NamespacedClient{}, errors.New("clients: fenced mutation missing client result")
		}
		return rowToNamespacedClient(*result.Client), nil
	case "idempotency_conflict":
		return NamespacedClient{}, ErrClientIdempotencyConflict
	case "operation_in_progress":
		return NamespacedClient{}, ErrClientOperationInProgress
	case "stale":
		return NamespacedClient{}, ErrStaleClientGeneration
	case "conflict":
		return NamespacedClient{}, ErrClientGenerationConflict
	case "exists":
		return NamespacedClient{}, ErrNamespacedClientExists
	case "missing":
		return NamespacedClient{}, ErrClientNotFound
	case "namespace_inactive":
		return NamespacedClient{}, ErrNamespaceInactive
	default:
		return NamespacedClient{}, fmt.Errorf("clients: unknown fenced mutation outcome %q", result.Outcome)
	}
}
