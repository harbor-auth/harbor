package clients

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor-auth/harbor/internal/gen/db"
)

// ErrNamespacedClientExists is returned when creating a namespaced client
// whose client_id already exists. relying_parties.client_id is the table's
// primary key, so this fires regardless of whether the existing row belongs
// to the same namespace, a different namespace, or no namespace at all —
// cloudapi maps it to 409 client_already_exists without naming the owner.
var ErrNamespacedClientExists = errors.New("clients: namespaced client already exists")

// NamespacedClient is an OIDC relying party owned by a Harbor Cloud
// namespace (internal/cloudapi's /admin/v1/namespaces/{namespace}/clients).
// It is the same relying_parties row RegisteredClient and oidc.Client read,
// scoped by NamespaceID and carrying DeletedAt for the soft-delete this
// store's SoftDelete performs.
type NamespacedClient struct {
	ClientID                string
	NamespaceID             string
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
	DeletedAt               *time.Time
}

// NewNamespacedClient contains the fields required to create a new
// namespace-owned client.
type NewNamespacedClient struct {
	ClientID                string
	NamespaceID             string
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

// UpdateNamespacedClient contains the fields that can be updated on an
// existing namespace-owned client. ClientSecretHash is nil-means-unchanged:
// the underlying query COALESCEs a NULL argument over the stored hash
// (db/queries/relying_parties.sql), so a caller updating only redirect_uris
// does not have to re-submit or blank out the secret hash.
type UpdateNamespacedClient struct {
	ClientID                string
	NamespaceID             string
	Name                    string
	RedirectURIs            []string
	ScopesAllowed           []string
	TokenEndpointAuthMethod string
	ClientSecretHash        []byte
}

// namespacedClientQuerier is the narrow interface over *db.Queries that
// DBNamespacedClientStore needs. Production code passes *db.Queries; tests
// pass a small fake.
type namespacedClientQuerier interface {
	CreateNamespacedClient(ctx context.Context, arg db.CreateNamespacedClientParams) (db.RelyingParty, error)
	GetNamespacedClient(ctx context.Context, arg db.GetNamespacedClientParams) (db.RelyingParty, error)
	ListNamespacedClients(ctx context.Context, namespaceID *string) ([]db.RelyingParty, error)
	UpdateNamespacedClient(ctx context.Context, arg db.UpdateNamespacedClientParams) (db.RelyingParty, error)
	SoftDeleteNamespacedClient(ctx context.Context, arg db.SoftDeleteNamespacedClientParams) error
}

// DBNamespacedClientStore implements namespace-scoped OIDC client CRUD over
// the relying_parties table (db/queries/relying_parties.sql's namespaced
// queries). It reuses the same persisted registry as the hot-path client
// lookup (DBClientRegistry) and RFC 7591/7592 registration
// (DBClientRegistrationStore) — there is no parallel store.
type DBNamespacedClientStore struct {
	q namespacedClientQuerier
}

// NewDBNamespacedClientStore returns a store backed by q. q is typically
// *db.Queries obtained from a pgx connection pool.
func NewDBNamespacedClientStore(q namespacedClientQuerier) *DBNamespacedClientStore {
	return &DBNamespacedClientStore{q: q}
}

// Create persists a new namespace-owned client. Returns
// ErrNamespacedClientExists if client_id is already taken.
func (s *DBNamespacedClientStore) Create(ctx context.Context, c NewNamespacedClient) (NamespacedClient, error) {
	var createdAt pgtype.Timestamptz
	if err := createdAt.Scan(c.CreatedAt); err != nil {
		return NamespacedClient{}, fmt.Errorf("namespaced client: parse created_at: %w", err)
	}

	namespaceID := c.NamespaceID
	var tokenEndpointAuthMethod *string
	if c.TokenEndpointAuthMethod != "" {
		tokenEndpointAuthMethod = &c.TokenEndpointAuthMethod
	}

	row, err := s.q.CreateNamespacedClient(ctx, db.CreateNamespacedClientParams{
		ClientID:                c.ClientID,
		Name:                    c.Name,
		SectorID:                c.SectorID,
		RedirectUris:            c.RedirectURIs,
		TokenFormat:             c.TokenFormat,
		ScopesAllowed:           c.ScopesAllowed,
		ClientSecretHash:        c.ClientSecretHash,
		GrantTypes:              c.GrantTypes,
		ResponseTypes:           c.ResponseTypes,
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		CreatedAt:               createdAt,
		NamespaceID:             &namespaceID,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return NamespacedClient{}, ErrNamespacedClientExists
		}
		return NamespacedClient{}, fmt.Errorf("namespaced client: create: %w", err)
	}
	return rowToNamespacedClient(row), nil
}

// Get retrieves a client by (clientID, namespaceID). Returns
// ErrClientNotFound if no live client with that client_id exists under that
// namespace — including when client_id exists but is owned by a different
// namespace, or has been soft-deleted, which the underlying query cannot
// distinguish from absence (db/queries/relying_parties.sql) and this store
// must not distinguish either: the caller (cloudapi) maps all three to the
// same 404 client_not_found so a cross-tenant probe learns nothing.
func (s *DBNamespacedClientStore) Get(ctx context.Context, clientID, namespaceID string) (NamespacedClient, error) {
	row, err := s.q.GetNamespacedClient(ctx, db.GetNamespacedClientParams{ClientID: clientID, NamespaceID: &namespaceID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return NamespacedClient{}, ErrClientNotFound
		}
		return NamespacedClient{}, fmt.Errorf("namespaced client: get: %w", err)
	}
	return rowToNamespacedClient(row), nil
}

// List returns every live client owned by namespaceID.
func (s *DBNamespacedClientStore) List(ctx context.Context, namespaceID string) ([]NamespacedClient, error) {
	rows, err := s.q.ListNamespacedClients(ctx, &namespaceID)
	if err != nil {
		return nil, fmt.Errorf("namespaced client: list: %w", err)
	}
	clients := make([]NamespacedClient, 0, len(rows))
	for _, row := range rows {
		clients = append(clients, rowToNamespacedClient(row))
	}
	return clients, nil
}

// Update modifies a namespace-owned client's mutable metadata. Returns
// ErrClientNotFound under the same absent-or-foreign-or-deleted conditions as
// Get. Immutable fields (client_id, sector_id, namespace_id, created_at) are
// not updated.
func (s *DBNamespacedClientStore) Update(ctx context.Context, c UpdateNamespacedClient) (NamespacedClient, error) {
	namespaceID := c.NamespaceID
	var tokenEndpointAuthMethod *string
	if c.TokenEndpointAuthMethod != "" {
		tokenEndpointAuthMethod = &c.TokenEndpointAuthMethod
	}

	row, err := s.q.UpdateNamespacedClient(ctx, db.UpdateNamespacedClientParams{
		ClientID:                c.ClientID,
		NamespaceID:             &namespaceID,
		Name:                    c.Name,
		RedirectUris:            c.RedirectURIs,
		ScopesAllowed:           c.ScopesAllowed,
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		ClientSecretHash:        c.ClientSecretHash,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return NamespacedClient{}, ErrClientNotFound
		}
		return NamespacedClient{}, fmt.Errorf("namespaced client: update: %w", err)
	}
	return rowToNamespacedClient(row), nil
}

// SoftDelete marks a namespace-owned client deleted. It does not error when
// clientID is absent, owned by a different namespace, or already deleted —
// the underlying UPDATE simply affects zero rows — so callers can implement
// the idempotent-delete contract (204, always, never revealing whether the
// id exists under another namespace) without a separate existence check.
func (s *DBNamespacedClientStore) SoftDelete(ctx context.Context, clientID, namespaceID string) error {
	if err := s.q.SoftDeleteNamespacedClient(ctx, db.SoftDeleteNamespacedClientParams{ClientID: clientID, NamespaceID: &namespaceID}); err != nil {
		return fmt.Errorf("namespaced client: soft delete: %w", err)
	}
	return nil
}

// isUniqueViolation reports whether err is a Postgres unique/primary-key
// constraint violation (SQLSTATE 23505). Mirrors cloudapi.isUniqueViolation;
// duplicated rather than shared because internal/cloudapi depends on
// internal/clients, never the reverse.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// rowToNamespacedClient maps a sqlc RelyingParty row to the domain type.
func rowToNamespacedClient(row db.RelyingParty) NamespacedClient {
	var tokenEndpointAuthMethod string
	if row.TokenEndpointAuthMethod != nil {
		tokenEndpointAuthMethod = *row.TokenEndpointAuthMethod
	}

	var namespaceID string
	if row.NamespaceID != nil {
		namespaceID = *row.NamespaceID
	}

	var createdAt time.Time
	if row.CreatedAt.Valid {
		createdAt = row.CreatedAt.Time
	}

	var deletedAt *time.Time
	if row.DeletedAt.Valid {
		deletedAt = &row.DeletedAt.Time
	}

	return NamespacedClient{
		ClientID:                row.ClientID,
		NamespaceID:             namespaceID,
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
		DeletedAt:               deletedAt,
	}
}
