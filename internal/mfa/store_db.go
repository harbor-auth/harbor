package mfa

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor-auth/harbor/internal/gen/db"
)

// mfaQuerier is the narrow sqlc surface DBStore needs. Depending on a subset
// (not *db.Queries) keeps this file testable with a fake and documents exactly
// which generated queries the MFA store uses.
type mfaQuerier interface {
	GetMFAFactor(ctx context.Context, id pgtype.UUID) (db.MfaFactor, error)
	ListMFAFactorsByUser(ctx context.Context, userID pgtype.UUID) ([]db.MfaFactor, error)
	CreateMFAFactor(ctx context.Context, arg db.CreateMFAFactorParams) (db.MfaFactor, error)
	DeleteMFAFactor(ctx context.Context, id pgtype.UUID) error
	MarkMFAFactorUsed(ctx context.Context, id pgtype.UUID) error
}

// DBStore implements Store backed by the sqlc queries over Postgres. It is safe
// for concurrent use (all state lives in the database).
type DBStore struct {
	q mfaQuerier
}

// NewDBStore returns a DBStore backed by the given querier.
func NewDBStore(q mfaQuerier) *DBStore {
	return &DBStore{q: q}
}

// GetFactor implements Store. A malformed ID and a missing row both collapse to
// ErrFactorNotFound so the lookup never reveals which case occurred.
func (s *DBStore) GetFactor(ctx context.Context, factorID string) (StoredFactor, error) {
	id, err := parseUUID(factorID)
	if err != nil {
		return StoredFactor{}, ErrFactorNotFound
	}
	row, err := s.q.GetMFAFactor(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return StoredFactor{}, ErrFactorNotFound
		}
		return StoredFactor{}, fmt.Errorf("mfa/store_db: get factor: %w", err)
	}
	return rowToStoredFactor(row), nil
}

// ListFactors implements Store: returns the user's factors newest-first. A
// user with no factors yields a nil slice (not an error).
func (s *DBStore) ListFactors(ctx context.Context, userID string) ([]StoredFactor, error) {
	uid, err := parseUUID(userID)
	if err != nil {
		return nil, fmt.Errorf("mfa/store_db: parse user ID %q: %w", userID, err)
	}
	rows, err := s.q.ListMFAFactorsByUser(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("mfa/store_db: list factors: %w", err)
	}
	factors := make([]StoredFactor, len(rows))
	for i, row := range rows {
		factors[i] = rowToStoredFactor(row)
	}
	return factors, nil
}

// CreateFactor implements Store: mints the factor's UUID and inserts the row,
// returning the persisted factor (with created-at populated by the DB).
func (s *DBStore) CreateFactor(ctx context.Context, params CreateFactorParams) (StoredFactor, error) {
	uid, err := parseUUID(params.UserID)
	if err != nil {
		return StoredFactor{}, fmt.Errorf("mfa/store_db: parse user ID %q: %w", params.UserID, err)
	}
	row, err := s.q.CreateMFAFactor(ctx, db.CreateMFAFactorParams{
		ID:       pgtype.UUID{Bytes: uuid.New(), Valid: true},
		Region:   params.Region,
		UserID:   uid,
		Type:     string(params.Type),
		Secret:   params.Secret,
		CodeHash: params.CodeHash,
	})
	if err != nil {
		return StoredFactor{}, fmt.Errorf("mfa/store_db: create factor: %w", err)
	}
	return rowToStoredFactor(row), nil
}

// DeleteFactor implements Store: removes the factor by ID (no-op if absent).
func (s *DBStore) DeleteFactor(ctx context.Context, factorID string) error {
	id, err := parseUUID(factorID)
	if err != nil {
		return fmt.Errorf("mfa/store_db: parse factor ID %q: %w", factorID, err)
	}
	if err := s.q.DeleteMFAFactor(ctx, id); err != nil {
		return fmt.Errorf("mfa/store_db: delete factor: %w", err)
	}
	return nil
}

// MarkUsed implements Store: burns a single-use factor. The underlying query
// only flips unused → used, so a double-spend or a missing factor is a no-op.
func (s *DBStore) MarkUsed(ctx context.Context, factorID string) error {
	id, err := parseUUID(factorID)
	if err != nil {
		return fmt.Errorf("mfa/store_db: parse factor ID %q: %w", factorID, err)
	}
	if err := s.q.MarkMFAFactorUsed(ctx, id); err != nil {
		return fmt.Errorf("mfa/store_db: mark used: %w", err)
	}
	return nil
}

// rowToStoredFactor maps a sqlc MfaFactor row to the store-level StoredFactor.
func rowToStoredFactor(row db.MfaFactor) StoredFactor {
	sf := StoredFactor{
		ID:       uuidToString(row.ID),
		UserID:   uuidToString(row.UserID),
		Region:   row.Region,
		Type:     FactorType(row.Type),
		Secret:   row.Secret,
		CodeHash: row.CodeHash,
		Used:     row.Used,
	}
	if row.CreatedAt.Valid {
		sf.CreatedAt = row.CreatedAt.Time
	}
	return sf
}

// parseUUID parses a UUID string into a pgtype.UUID for query parameters.
func parseUUID(s string) (pgtype.UUID, error) {
	var id pgtype.UUID
	if err := id.Scan(s); err != nil {
		return pgtype.UUID{}, fmt.Errorf("invalid uuid %q: %w", s, err)
	}
	return id, nil
}

// uuidToString renders a pgtype.UUID as its canonical string form, or "" when
// the UUID is NULL/invalid.
func uuidToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return uuid.UUID(u.Bytes).String()
}

// Compile-time assertion: DBStore implements Store.
var _ Store = (*DBStore)(nil)
