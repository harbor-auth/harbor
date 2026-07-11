package clients

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor/harbor/internal/gen/db"
	"github.com/harbor/harbor/internal/oidc"
)

// grantQuerier is the narrow interface over *db.Queries that DBGrantStore
// needs. Production code passes *db.Queries; tests pass a small fake.
type grantQuerier interface {
	FindGrantByUserClient(ctx context.Context, arg db.FindGrantByUserClientParams) (db.Grant, error)
	CreateGrant(ctx context.Context, arg db.CreateGrantParams) (db.Grant, error)
	RevokeGrant(ctx context.Context, id pgtype.UUID) error
	ListGrantsByUser(ctx context.Context, userID pgtype.UUID) ([]db.Grant, error)
}

// DBGrantStore is a sqlc-backed oidc.GrantStore. It persists consent grants in
// the grants table (docs/DESIGN.md §10) — user-owned rows that carry the
// pairwise_sub the RP will see (DESIGN §3.2) and the consented scopes.
type DBGrantStore struct {
	q grantQuerier
}

// NewDBGrantStore returns a GrantStore backed by q. q is typically
// *db.Queries obtained from a pgx connection pool.
func NewDBGrantStore(q grantQuerier) *DBGrantStore {
	return &DBGrantStore{q: q}
}

// FindGrant implements oidc.GrantStore. Returns (Grant{}, false, nil) when no
// active grant exists for (userID, clientID). Any DB error propagates as the
// third return value.
func (s *DBGrantStore) FindGrant(ctx context.Context, userID, clientID string) (oidc.Grant, bool, error) {
	uUID, err := parseUUID(userID)
	if err != nil {
		return oidc.Grant{}, false, fmt.Errorf("clients: FindGrant: invalid userID: %w", err)
	}
	row, err := s.q.FindGrantByUserClient(ctx, db.FindGrantByUserClientParams{
		UserID:   uUID,
		ClientID: clientID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return oidc.Grant{}, false, nil
		}
		return oidc.Grant{}, false, fmt.Errorf("clients: FindGrant: %w", err)
	}
	return rowToGrant(row), true, nil
}

// CreateGrant implements oidc.GrantStore. It mints a new UUID for the grant ID
// and stamps CreatedAt via the DB DEFAULT (now()). The region field on g
// satisfies the user-owned-row contract (DESIGN §10).
func (s *DBGrantStore) CreateGrant(ctx context.Context, g oidc.NewGrant) (oidc.Grant, error) {
	uUID, err := parseUUID(g.UserID)
	if err != nil {
		return oidc.Grant{}, fmt.Errorf("clients: CreateGrant: invalid userID: %w", err)
	}
	var id pgtype.UUID
	if err := id.Scan(uuid.NewString()); err != nil {
		return oidc.Grant{}, fmt.Errorf("clients: CreateGrant: mint id: %w", err)
	}
	row, err := s.q.CreateGrant(ctx, db.CreateGrantParams{
		ID:          id,
		Region:      g.Region,
		UserID:      uUID,
		ClientID:    g.ClientID,
		PairwiseSub: g.PairwiseSub,
		Scopes:      g.Scopes,
	})
	if err != nil {
		return oidc.Grant{}, fmt.Errorf("clients: CreateGrant: %w", err)
	}
	return rowToGrant(row), nil
}

// RevokeGrant implements oidc.GrantStore. id must be a UUID string.
func (s *DBGrantStore) RevokeGrant(ctx context.Context, id string) error {
	gUID, err := parseUUID(id)
	if err != nil {
		return fmt.Errorf("clients: RevokeGrant: invalid id: %w", err)
	}
	if err := s.q.RevokeGrant(ctx, gUID); err != nil {
		return fmt.Errorf("clients: RevokeGrant: %w", err)
	}
	return nil
}

// ListGrantsByUser implements oidc.GrantStore.
func (s *DBGrantStore) ListGrantsByUser(ctx context.Context, userID string) ([]oidc.Grant, error) {
	uUID, err := parseUUID(userID)
	if err != nil {
		return nil, fmt.Errorf("clients: ListGrantsByUser: invalid userID: %w", err)
	}
	rows, err := s.q.ListGrantsByUser(ctx, uUID)
	if err != nil {
		return nil, fmt.Errorf("clients: ListGrantsByUser: %w", err)
	}
	out := make([]oidc.Grant, len(rows))
	for i, r := range rows {
		out[i] = rowToGrant(r)
	}
	return out, nil
}

// rowToGrant maps a sqlc Grant row to the oidc domain type. It is a pure
// function so it is directly unit-testable without a DB.
func rowToGrant(row db.Grant) oidc.Grant {
	return oidc.Grant{
		ID:          uuidToString(row.ID),
		Region:      row.Region,
		UserID:      uuidToString(row.UserID),
		ClientID:    row.ClientID,
		PairwiseSub: row.PairwiseSub,
		Scopes:      row.Scopes,
		CreatedAt:   row.CreatedAt.Time, // zero if !Valid (DB DEFAULT never NULL)
		RevokedAt:   timePtrFromPgtz(row.RevokedAt),
	}
}

// parseUUID converts a string UUID to pgtype.UUID.
func parseUUID(s string) (pgtype.UUID, error) {
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		return pgtype.UUID{}, err
	}
	return u, nil
}

// uuidToString converts a pgtype.UUID to its canonical string form. Returns the
// zero UUID string if the value is not valid.
func uuidToString(u pgtype.UUID) string {
	if !u.Valid {
		return "00000000-0000-0000-0000-000000000000"
	}
	// pgtype.UUID bytes are the raw 16-byte representation.
	b := u.Bytes
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// timePtrFromPgtz converts a pgtype.Timestamptz to a *time.Time. nil = invalid/zero.
func timePtrFromPgtz(ts pgtype.Timestamptz) *time.Time {
	if !ts.Valid {
		return nil
	}
	t := ts.Time
	return &t
}
