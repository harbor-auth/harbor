package clients

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor/harbor/internal/gen/db"
)

// revokedJTIQuerier is the narrow sqlc surface DBRevokedJTIStore needs.
// Using a subset keeps this file testable with a fake and documents exactly
// which generated queries the revocation path depends on.
type revokedJTIQuerier interface {
	InsertRevokedJTI(ctx context.Context, arg db.InsertRevokedJTIParams) (db.RevokedJti, error)
	GetRevokedJTI(ctx context.Context, jti string) (db.RevokedJti, error)
	ListActiveRevokedJTIs(ctx context.Context) ([]db.RevokedJti, error)
	GCExpiredRevokedJTIs(ctx context.Context) error
}

// RevokedJTI represents a revoked JWT ID in the domain layer.
type RevokedJTI struct {
	JTI       string
	RevokedAt time.Time
	Reason    string
	ExpiresAt time.Time
}

// DBRevokedJTIStore implements the revoked JTI persistence layer backed by
// the revoked_jtis table (docs/DESIGN.md §3.5). This is the persistent source
// of truth for emergency JWT revocation; the bloom filter is rehydrated from
// this store on startup.
type DBRevokedJTIStore struct {
	q revokedJTIQuerier
}

// NewDBRevokedJTIStore returns a RevokedJTIStore backed by q. q is typically
// *db.Queries obtained from a pgx connection pool.
func NewDBRevokedJTIStore(q revokedJTIQuerier) *DBRevokedJTIStore {
	return &DBRevokedJTIStore{q: q}
}

// Insert upserts a revoked JTI. On conflict (re-revocation of same JTI),
// updates reason/expires_at to latest values. This is idempotent so retries
// and duplicate pub/sub messages are safe.
func (s *DBRevokedJTIStore) Insert(ctx context.Context, jti, reason string, expiresAt time.Time) (RevokedJTI, error) {
	var expTS pgtype.Timestamptz
	if err := expTS.Scan(expiresAt); err != nil {
		return RevokedJTI{}, fmt.Errorf("revoked_jtis: parse expires_at: %w", err)
	}
	row, err := s.q.InsertRevokedJTI(ctx, db.InsertRevokedJTIParams{
		Jti:       jti,
		Reason:    reason,
		ExpiresAt: expTS,
	})
	if err != nil {
		return RevokedJTI{}, fmt.Errorf("revoked_jtis: insert: %w", err)
	}
	return rowToRevokedJTI(row), nil
}

// GetByJTI checks if a specific JTI is revoked. Returns (RevokedJTI{}, false, nil)
// when the JTI is not found. Used for introspection fallback when the bloom
// filter returns a hit (confirms true positive vs false positive).
func (s *DBRevokedJTIStore) GetByJTI(ctx context.Context, jti string) (RevokedJTI, bool, error) {
	row, err := s.q.GetRevokedJTI(ctx, jti)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RevokedJTI{}, false, nil
		}
		return RevokedJTI{}, false, fmt.Errorf("revoked_jtis: get by jti: %w", err)
	}
	return rowToRevokedJTI(row), true, nil
}

// ListActive returns all JTIs that are still within their JWT's original
// expiry window. Used to rehydrate the bloom filter on startup.
func (s *DBRevokedJTIStore) ListActive(ctx context.Context) ([]RevokedJTI, error) {
	rows, err := s.q.ListActiveRevokedJTIs(ctx)
	if err != nil {
		return nil, fmt.Errorf("revoked_jtis: list active: %w", err)
	}
	out := make([]RevokedJTI, len(rows))
	for i, r := range rows {
		out[i] = rowToRevokedJTI(r)
	}
	return out, nil
}

// GCExpired deletes entries for JWTs that have expired — their JTIs no longer
// need revocation (the JWT itself is invalid). Run nightly as background
// cleanup, off the hot path.
func (s *DBRevokedJTIStore) GCExpired(ctx context.Context) error {
	if err := s.q.GCExpiredRevokedJTIs(ctx); err != nil {
		return fmt.Errorf("revoked_jtis: gc expired: %w", err)
	}
	return nil
}

// rowToRevokedJTI maps a sqlc RevokedJti row to the domain type. It is a pure
// function so it is directly unit-testable without a DB.
func rowToRevokedJTI(row db.RevokedJti) RevokedJTI {
	var revokedAt, expiresAt time.Time
	if row.RevokedAt.Valid {
		revokedAt = row.RevokedAt.Time
	}
	if row.ExpiresAt.Valid {
		expiresAt = row.ExpiresAt.Time
	}
	return RevokedJTI{
		JTI:       row.Jti,
		RevokedAt: revokedAt,
		Reason:    row.Reason,
		ExpiresAt: expiresAt,
	}
}
