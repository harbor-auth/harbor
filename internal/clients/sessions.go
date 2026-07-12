package clients

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor/harbor/internal/gen/db"
	"github.com/harbor/harbor/internal/oidc"
)

// sessionQuerier is the narrow sqlc surface DBSessionStore needs. Using a
// subset keeps this file testable with a fake and documents exactly which
// generated queries the refresh-token path depends on.
type sessionQuerier interface {
	CreateSession(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
	GetSession(ctx context.Context, id pgtype.UUID) (db.Session, error)
	GetActiveSession(ctx context.Context, id pgtype.UUID) (db.Session, error)
	ListSessionsByUser(ctx context.Context, userID pgtype.UUID) ([]db.Session, error)
	RevokeSession(ctx context.Context, id pgtype.UUID) error
	RevokeSessionsByUser(ctx context.Context, userID pgtype.UUID) error
}

// DBSessionStore implements oidc.SessionStore over the sessions table
// (docs/DESIGN.md §3.5, §10). Each method converts domain types to/from sqlc
// types; only the token HASH is ever handled here — the plaintext refresh token
// never enters this package (§7.4).
type DBSessionStore struct {
	q sessionQuerier
}

// NewDBSessionStore wraps a sqlc Queries (or any sessionQuerier).
func NewDBSessionStore(q sessionQuerier) *DBSessionStore {
	return &DBSessionStore{q: q}
}

// Compile-time proof that DBSessionStore implements oidc.SessionStore.
var _ oidc.SessionStore = (*DBSessionStore)(nil)

// CreateSession implements oidc.SessionStore.
func (s *DBSessionStore) CreateSession(ctx context.Context, rs oidc.RefreshSession) error {
	var id pgtype.UUID
	if err := id.Scan(rs.ID); err != nil {
		return fmt.Errorf("sessions: parse session ID %q: %w", rs.ID, err)
	}
	var userID pgtype.UUID
	if err := userID.Scan(rs.UserID); err != nil {
		return fmt.Errorf("sessions: parse user ID %q: %w", rs.UserID, err)
	}
	var deviceLabel *string
	if rs.DeviceLabel != "" {
		label := rs.DeviceLabel
		deviceLabel = &label
	}
	var expiresAt pgtype.Timestamptz
	if err := expiresAt.Scan(rs.ExpiresAt); err != nil {
		return fmt.Errorf("sessions: parse expires_at: %w", err)
	}
	_, err := s.q.CreateSession(ctx, db.CreateSessionParams{
		ID:               id,
		Region:           rs.Region,
		UserID:           userID,
		DeviceLabel:      deviceLabel,
		RefreshTokenHash: rs.TokenHash,
		ExpiresAt:        expiresAt,
	})
	return err
}

// GetSessionByTokenHash implements oidc.SessionStore.
//
// SCAFFOLD: the sessions table is currently indexed by id (UUID), not by
// refresh_token_hash, so there is no by-hash lookup query yet. A real deployment
// MUST add a UNIQUE index on refresh_token_hash and a GetSessionByHash sqlc
// query (see docs/plans/refresh-token-rotation.md "Risks"). Until then this
// returns not-found so the DB path fails closed rather than silently accepting
// tokens it cannot verify.
func (s *DBSessionStore) GetSessionByTokenHash(_ context.Context, _ []byte) (oidc.RefreshSession, error) {
	return oidc.RefreshSession{}, oidc.ErrRefreshTokenNotFound
}

// RevokeSession implements oidc.SessionStore.
func (s *DBSessionStore) RevokeSession(ctx context.Context, id string) error {
	var uid pgtype.UUID
	if err := uid.Scan(id); err != nil {
		return fmt.Errorf("sessions: parse session ID %q: %w", id, err)
	}
	return s.q.RevokeSession(ctx, uid)
}

// RevokeSessionsByUserClient implements oidc.SessionStore (theft signal family
// revoke). The sessions table has no client_id column yet, so we revoke ALL of
// the user's active sessions — a conservative superset of the (user, client)
// family, equivalent to "sign out everywhere" for that user. A future migration
// can add client_id for finer-grained revocation.
func (s *DBSessionStore) RevokeSessionsByUserClient(ctx context.Context, userID, _ string) error {
	var uid pgtype.UUID
	if err := uid.Scan(userID); err != nil {
		return fmt.Errorf("sessions: parse user ID %q: %w", userID, err)
	}
	return s.q.RevokeSessionsByUser(ctx, uid)
}

// isRevoked reports whether a db.Session row has been revoked.
func isRevoked(row db.Session) bool {
	return row.RevokedAt.Valid && !row.RevokedAt.Time.IsZero()
}
