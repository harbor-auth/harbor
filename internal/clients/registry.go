package clients

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/harbor/harbor/internal/gen/db"
	"github.com/harbor/harbor/internal/oidc"
)

// rpQuerier is the narrow interface over *db.Queries that DBClientRegistry
// needs. Production code passes *db.Queries; tests pass a small fake.
type rpQuerier interface {
	GetRelyingParty(ctx context.Context, clientID string) (db.RelyingParty, error)
}

// DBClientRegistry is a sqlc-backed oidc.ClientRegistry. It reads RP
// registrations from the relying_parties table (docs/DESIGN.md §10) on every
// Lookup call. A caching layer (e.g. in-process TTL cache) can be added later
// without changing the interface.
type DBClientRegistry struct {
	q rpQuerier
}

// NewDBClientRegistry returns a ClientRegistry backed by q. q is typically
// *db.Queries obtained from a pgx connection pool.
func NewDBClientRegistry(q rpQuerier) *DBClientRegistry {
	return &DBClientRegistry{q: q}
}

// Lookup implements oidc.ClientRegistry. Returns (Client, false) for an unknown
// or missing client_id; propagates DB errors as (Client{}, false) would mask
// them, so the error is returned instead — the hot path treats any non-nil error
// as a server error.
func (r *DBClientRegistry) Lookup(ctx context.Context, clientID string) (oidc.Client, bool) {
	row, err := r.q.GetRelyingParty(ctx, clientID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return oidc.Client{}, false
		}
		// DB error: return not-found so the caller surfaces server_error rather
		// than redirecting to an unverified URI (open-redirect defence).
		return oidc.Client{}, false
	}
	return rowToClient(row), true
}

// rowToClient maps a sqlc RelyingParty row to the oidc domain type. It is a
// pure function so it is directly unit-testable without a DB.
func rowToClient(row db.RelyingParty) oidc.Client {
	return oidc.Client{
		ID:            row.ClientID,
		SectorID:      row.SectorID,
		RedirectURIs:  row.RedirectUris,
		ScopesAllowed: row.ScopesAllowed,
	}
}
