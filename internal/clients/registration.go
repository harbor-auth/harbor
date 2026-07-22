package clients

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor-auth/harbor/internal/gen/db"
)

// ErrClientNotFound is returned when a client lookup finds no matching row.
var ErrClientNotFound = errors.New("client not found")

// ErrInvalidRegToken is returned when the registration access token does not
// match the stored hash.
var ErrInvalidRegToken = errors.New("invalid registration access token")

// RegisteredClient represents a dynamically-registered OAuth 2.0 client
// (RFC 7591). It contains all the metadata returned from the registration
// endpoint and needed for the configuration endpoint (RFC 7592).
type RegisteredClient struct {
	ClientID                string
	Name                    string
	SectorID                string
	RedirectURIs            []string
	TokenFormat             string
	ScopesAllowed           []string
	ClientSecretHash        []byte
	GrantTypes              []string
	ResponseTypes           []string
	TokenEndpointAuthMethod string
	CreatedAt               time.Time
}

// NewRegisteredClient contains the fields required to create a new
// dynamically-registered client.
type NewRegisteredClient struct {
	ClientID                    string
	Name                        string
	SectorID                    string
	RedirectURIs                []string
	TokenFormat                 string
	ScopesAllowed               []string
	ClientSecretHash            []byte
	RegistrationAccessTokenHash []byte
	GrantTypes                  []string
	ResponseTypes               []string
	TokenEndpointAuthMethod     string
	CreatedAt                   time.Time
}

// UpdateRegisteredClient contains the fields that can be updated on an
// existing dynamically-registered client (RFC 7592 PUT).
type UpdateRegisteredClient struct {
	ClientID                    string
	Name                        string
	RedirectURIs                []string
	TokenFormat                 string
	ScopesAllowed               []string
	ClientSecretHash            []byte
	RegistrationAccessTokenHash []byte
	GrantTypes                  []string
	ResponseTypes               []string
	TokenEndpointAuthMethod     string
}

// registrationQuerier is the narrow interface over *db.Queries that
// DBClientRegistrationStore needs. Production code passes *db.Queries;
// tests pass a small fake.
type registrationQuerier interface {
	CreateRegisteredClient(ctx context.Context, arg db.CreateRegisteredClientParams) (db.RelyingParty, error)
	GetRegisteredClient(ctx context.Context, registrationAccessTokenHash []byte) (db.RelyingParty, error)
	GetRelyingParty(ctx context.Context, clientID string) (db.RelyingParty, error)
	UpdateRegisteredClient(ctx context.Context, arg db.UpdateRegisteredClientParams) (db.RelyingParty, error)
	DeleteRelyingParty(ctx context.Context, clientID string) error
}

// DBClientRegistrationStore implements RFC 7591/7592 client registration
// operations over the relying_parties table. It reuses the same persisted
// registry as the hot-path client lookup (DBClientRegistry) — there is no
// parallel store.
type DBClientRegistrationStore struct {
	q registrationQuerier
}

// NewDBClientRegistrationStore returns a store backed by q. q is typically
// *db.Queries obtained from a pgx connection pool.
func NewDBClientRegistrationStore(q registrationQuerier) *DBClientRegistrationStore {
	return &DBClientRegistrationStore{q: q}
}

// Create persists a new dynamically-registered client (RFC 7591 POST /register).
// The caller must have already generated the client_id, hashed the client_secret
// (if confidential), and hashed the registration_access_token.
func (s *DBClientRegistrationStore) Create(ctx context.Context, c NewRegisteredClient) (RegisteredClient, error) {
	var createdAt pgtype.Timestamptz
	if err := createdAt.Scan(c.CreatedAt); err != nil {
		return RegisteredClient{}, fmt.Errorf("registration: parse created_at: %w", err)
	}

	var tokenEndpointAuthMethod *string
	if c.TokenEndpointAuthMethod != "" {
		tokenEndpointAuthMethod = &c.TokenEndpointAuthMethod
	}

	row, err := s.q.CreateRegisteredClient(ctx, db.CreateRegisteredClientParams{
		ClientID:                    c.ClientID,
		Name:                        c.Name,
		SectorID:                    c.SectorID,
		RedirectUris:                c.RedirectURIs,
		TokenFormat:                 c.TokenFormat,
		ScopesAllowed:               c.ScopesAllowed,
		ClientSecretHash:            c.ClientSecretHash,
		RegistrationAccessTokenHash: c.RegistrationAccessTokenHash,
		GrantTypes:                  c.GrantTypes,
		ResponseTypes:               c.ResponseTypes,
		TokenEndpointAuthMethod:     tokenEndpointAuthMethod,
		CreatedAt:                   createdAt,
	})
	if err != nil {
		return RegisteredClient{}, fmt.Errorf("registration: create: %w", err)
	}
	return rowToRegisteredClient(row), nil
}

// Get retrieves a client by client_id. Returns ErrClientNotFound if no client
// exists with that ID.
func (s *DBClientRegistrationStore) Get(ctx context.Context, clientID string) (RegisteredClient, error) {
	row, err := s.q.GetRelyingParty(ctx, clientID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RegisteredClient{}, ErrClientNotFound
		}
		return RegisteredClient{}, fmt.Errorf("registration: get: %w", err)
	}
	return rowToRegisteredClient(row), nil
}

// VerifyRegToken verifies a registration access token (RFC 7592) and returns
// the associated client. It hashes the provided token with SHA-256 and performs
// a constant-time comparison against the stored hash.
//
// Returns ErrInvalidRegToken if the token does not match any stored hash.
// This is the primary authentication mechanism for the client configuration
// endpoint (RFC 7592 GET/PUT/DELETE).
func (s *DBClientRegistrationStore) VerifyRegToken(ctx context.Context, token string) (RegisteredClient, error) {
	if token == "" {
		return RegisteredClient{}, ErrInvalidRegToken
	}

	// Hash the token with SHA-256 (same algorithm used at registration time).
	tokenHash := sha256.Sum256([]byte(token))

	// Look up by hash. The DB query uses an exact match on the hash column.
	row, err := s.q.GetRegisteredClient(ctx, tokenHash[:])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RegisteredClient{}, ErrInvalidRegToken
		}
		return RegisteredClient{}, fmt.Errorf("registration: verify token: %w", err)
	}

	// Constant-time comparison as a defence-in-depth measure. The DB already
	// did an exact match, but this guards against any hypothetical DB-level
	// timing side-channel (e.g. index scan short-circuiting on prefix mismatch).
	if subtle.ConstantTimeCompare(row.RegistrationAccessTokenHash, tokenHash[:]) != 1 {
		return RegisteredClient{}, ErrInvalidRegToken
	}

	return rowToRegisteredClient(row), nil
}

// Update modifies a dynamically-registered client's metadata (RFC 7592 PUT).
// Returns ErrClientNotFound if no client exists with the given client_id.
// Immutable fields (client_id, sector_id, created_at) are not updated.
func (s *DBClientRegistrationStore) Update(ctx context.Context, c UpdateRegisteredClient) (RegisteredClient, error) {
	var tokenEndpointAuthMethod *string
	if c.TokenEndpointAuthMethod != "" {
		tokenEndpointAuthMethod = &c.TokenEndpointAuthMethod
	}

	row, err := s.q.UpdateRegisteredClient(ctx, db.UpdateRegisteredClientParams{
		ClientID:                    c.ClientID,
		Name:                        c.Name,
		RedirectUris:                c.RedirectURIs,
		TokenFormat:                 c.TokenFormat,
		ScopesAllowed:               c.ScopesAllowed,
		ClientSecretHash:            c.ClientSecretHash,
		RegistrationAccessTokenHash: c.RegistrationAccessTokenHash,
		GrantTypes:                  c.GrantTypes,
		ResponseTypes:               c.ResponseTypes,
		TokenEndpointAuthMethod:     tokenEndpointAuthMethod,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RegisteredClient{}, ErrClientNotFound
		}
		return RegisteredClient{}, fmt.Errorf("registration: update: %w", err)
	}
	return rowToRegisteredClient(row), nil
}

// Delete removes a client registration (RFC 7592 DELETE). This is a hard delete
// — the client_id may be reused after deletion. Returns nil if the client did
// not exist (idempotent).
func (s *DBClientRegistrationStore) Delete(ctx context.Context, clientID string) error {
	if err := s.q.DeleteRelyingParty(ctx, clientID); err != nil {
		return fmt.Errorf("registration: delete: %w", err)
	}
	return nil
}

// rowToRegisteredClient maps a sqlc RelyingParty row to the domain type.
func rowToRegisteredClient(row db.RelyingParty) RegisteredClient {
	var tokenEndpointAuthMethod string
	if row.TokenEndpointAuthMethod != nil {
		tokenEndpointAuthMethod = *row.TokenEndpointAuthMethod
	}

	var createdAt time.Time
	if row.CreatedAt.Valid {
		createdAt = row.CreatedAt.Time
	}

	return RegisteredClient{
		ClientID:                row.ClientID,
		Name:                    row.Name,
		SectorID:                row.SectorID,
		RedirectURIs:            row.RedirectUris,
		TokenFormat:             row.TokenFormat,
		ScopesAllowed:           row.ScopesAllowed,
		ClientSecretHash:        row.ClientSecretHash,
		GrantTypes:              row.GrantTypes,
		ResponseTypes:           row.ResponseTypes,
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		CreatedAt:               createdAt,
	}
}
