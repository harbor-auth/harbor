package clients

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"

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
	// logger is an atomic.Pointer so WithLogger may be called during setup on a
	// different goroutine from a concurrent Lookup without a data race.
	logger atomic.Pointer[slog.Logger]
}

// NewDBClientRegistry returns a ClientRegistry backed by q. q is typically
// *db.Queries obtained from a pgx connection pool. It logs swallowed DB errors
// via slog.Default(); call WithLogger to route them to the service logger.
func NewDBClientRegistry(q rpQuerier) *DBClientRegistry {
	r := &DBClientRegistry{q: q}
	r.logger.Store(slog.Default())
	return r
}

// WithLogger sets the logger used to record the DB errors that Lookup must
// otherwise swallow (its interface returns no error). Wiring a real logger here
// is what makes a DB outage diagnosable instead of masquerading as an unknown
// client. A nil logger is ignored (the slog.Default() set in the constructor is
// kept). The store is atomic, so this is safe to call concurrently with Lookup.
func (r *DBClientRegistry) WithLogger(logger *slog.Logger) *DBClientRegistry {
	if logger != nil {
		r.logger.Store(logger)
	}
	return r
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
		// DB error: log it, then return not-found so the caller surfaces
		// server_error rather than redirecting to an unverified URI (open-redirect
		// defence). We must not redirect to an unproven URI even during a DB
		// outage, but the swallowed error is logged so the outage is diagnosable
		// (a degraded DB otherwise looks identical to an unknown client_id).
		r.logger.Load().ErrorContext(ctx, "client registry DB lookup failed",
			slog.String("client_id", clientID),
			slog.Any("error", err))
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
