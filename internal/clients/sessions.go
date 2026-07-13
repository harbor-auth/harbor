package clients

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
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
	GetSessionByHash(ctx context.Context, refreshTokenHash []byte) (db.Session, error)
	ListSessionsByUser(ctx context.Context, userID pgtype.UUID) ([]db.Session, error)
	RevokeSession(ctx context.Context, id pgtype.UUID) error
	// RevokeSessionsByUser is retained for the future "sign out everywhere"
	// (global user logout) path; the hot-path theft-signal uses RevokeSessionsByUserClient.
	RevokeSessionsByUser(ctx context.Context, userID pgtype.UUID) error
	RevokeSessionsByUserClient(ctx context.Context, arg db.RevokeSessionsByUserClientParams) error
}

// txBeginner is satisfied by *pgxpool.Pool and enables atomic rotation via
// a real DB transaction. Nil disables the transaction path (test/dev fallback).
type txBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// DBSessionStore implements oidc.SessionStore over the sessions table
// (docs/DESIGN.md §3.5, §10). Each method converts domain types to/from sqlc
// types; only the token HASH is ever handled here — the plaintext refresh token
// never enters this package (§7.4).
type DBSessionStore struct {
	q  sessionQuerier
	tx txBeginner // nil → sequential fallback in RotateSession
}

// NewDBSessionStore wraps a sqlc Queries (or any sessionQuerier).
func NewDBSessionStore(q sessionQuerier) *DBSessionStore {
	return &DBSessionStore{q: q}
}

// WithPool enables atomic single-transaction rotation via the given pool.
// Call this when wiring DBSessionStore in production (harbor-mgmt or session
// service); omitting it falls back to the sequential revoke+create path.
func (s *DBSessionStore) WithPool(p txBeginner) *DBSessionStore {
	s.tx = p
	return s
}

// Compile-time proof that DBSessionStore implements oidc.SessionStore.
var _ oidc.SessionStore = (*DBSessionStore)(nil)

// buildCreateSessionParams converts a domain RefreshSession into sqlc
// CreateSessionParams, parsing the UUIDs and normalising the optional device
// label. Shared by CreateSession and RotateSession so the two write paths
// cannot silently diverge.
func buildCreateSessionParams(rs oidc.RefreshSession) (db.CreateSessionParams, error) {
	var id pgtype.UUID
	if err := id.Scan(rs.ID); err != nil {
		return db.CreateSessionParams{}, fmt.Errorf("sessions: parse session ID %q: %w", rs.ID, err)
	}
	var userID pgtype.UUID
	if err := userID.Scan(rs.UserID); err != nil {
		return db.CreateSessionParams{}, fmt.Errorf("sessions: parse user ID %q: %w", rs.UserID, err)
	}
	var deviceLabel *string
	if rs.DeviceLabel != "" {
		label := rs.DeviceLabel
		deviceLabel = &label
	}
	var expiresAt pgtype.Timestamptz
	if err := expiresAt.Scan(rs.ExpiresAt); err != nil {
		return db.CreateSessionParams{}, fmt.Errorf("sessions: parse expires_at: %w", err)
	}
	return db.CreateSessionParams{
		ID:               id,
		Region:           rs.Region,
		UserID:           userID,
		ClientID:         rs.ClientID,
		DeviceLabel:      deviceLabel,
		RefreshTokenHash: rs.TokenHash,
		ExpiresAt:        expiresAt,
	}, nil
}

// CreateSession implements oidc.SessionStore.
func (s *DBSessionStore) CreateSession(ctx context.Context, rs oidc.RefreshSession) error {
	params, err := buildCreateSessionParams(rs)
	if err != nil {
		return err
	}
	_, err = s.q.CreateSession(ctx, params)
	return err
}

// GetSessionByTokenHash implements oidc.SessionStore. It returns the session
// row regardless of revocation / expiry status — the caller (oidc.Service.Refresh)
// needs to see revoked rows to fire the theft-signal family-revoke path
// (INV-REFRESH-THEFT-SIGNAL-FAMILY-REVOKE). The UNIQUE index added in migration
// 0004 makes this lookup O(log n) and enforces one-token-per-session.
func (s *DBSessionStore) GetSessionByTokenHash(ctx context.Context, hash []byte) (oidc.RefreshSession, error) {
	row, err := s.q.GetSessionByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return oidc.RefreshSession{}, oidc.ErrRefreshTokenNotFound
		}
		// Propagate transient DB errors so the caller returns a 5xx, not a
		// misleading invalid_grant. Masking DB failures as "token not found"
		// would silently reject valid tokens during outages.
		return oidc.RefreshSession{}, fmt.Errorf("sessions: get by hash: %w", err)
	}
	sess := rowToRefreshSession(row)
	// Revoked: return the populated session so the caller can fire the
	// theft-signal family revoke (INV-REFRESH-THEFT-SIGNAL-FAMILY-REVOKE).
	if isRevoked(row) {
		return sess, oidc.ErrRefreshTokenRevoked
	}
	// Expired (or missing expiry — fail closed): indistinguishable from
	// unknown to the caller. A NULL expires_at is treated as already-expired
	// so a misconfigured row doesn't become a permanent session.
	if !row.ExpiresAt.Valid || time.Now().After(row.ExpiresAt.Time) {
		return oidc.RefreshSession{}, oidc.ErrRefreshTokenNotFound
	}
	return sess, nil
}

// RevokeSession implements oidc.SessionStore.
func (s *DBSessionStore) RevokeSession(ctx context.Context, id string) error {
	var uid pgtype.UUID
	if err := uid.Scan(id); err != nil {
		return fmt.Errorf("sessions: parse session ID %q: %w", id, err)
	}
	return s.q.RevokeSession(ctx, uid)
}

// RotateSession implements oidc.SessionStore. It atomically revokes oldID and
// creates newSession. When a pool is wired (WithPool), both operations execute
// inside a single transaction so a crash between them cannot leave the user
// locked out. Without a pool (test/dev), it falls back to sequential
// revoke+create (same behaviour as before this change).
func (s *DBSessionStore) RotateSession(ctx context.Context, oldID string, newSession oidc.RefreshSession) error {
	if s.tx == nil {
		// No transactor: sequential best-effort (tests, dev without a pool).
		if err := s.RevokeSession(ctx, oldID); err != nil {
			return fmt.Errorf("sessions: rotate (revoke): %w", err)
		}
		return s.CreateSession(ctx, newSession)
	}
	txn, err := s.tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("sessions: begin rotation tx: %w", err)
	}
	defer txn.Rollback(ctx) //nolint:errcheck // Rollback after Commit is a no-op (returns pgx.ErrTxClosed); unrecoverable from a deferred call.

	qtx := db.New(txn)

	var oldUID pgtype.UUID
	if err := oldUID.Scan(oldID); err != nil {
		return fmt.Errorf("sessions: parse old session ID %q: %w", oldID, err)
	}
	if err := qtx.RevokeSession(ctx, oldUID); err != nil {
		return fmt.Errorf("sessions: rotate (revoke in tx): %w", err)
	}

	params, err := buildCreateSessionParams(newSession)
	if err != nil {
		return fmt.Errorf("sessions: rotate (build params): %w", err)
	}
	if _, err := qtx.CreateSession(ctx, params); err != nil {
		return fmt.Errorf("sessions: rotate (create in tx): %w", err)
	}

	return txn.Commit(ctx)
}

// RevokeSessionsByUserClient implements oidc.SessionStore (theft-signal family
// revoke; DESIGN §3.5, §11.7). Revokes only the active sessions belonging to
// the (userID, clientID) pair — a compromised token at one RP no longer forces
// re-authentication at every other RP the user has sessions with.
// The partial index idx_sessions_user_client (migration 0005) makes this O(log n).
func (s *DBSessionStore) RevokeSessionsByUserClient(ctx context.Context, userID, clientID string) error {
	var uid pgtype.UUID
	if err := uid.Scan(userID); err != nil {
		return fmt.Errorf("sessions: parse user ID %q: %w", userID, err)
	}
	return s.q.RevokeSessionsByUserClient(ctx, db.RevokeSessionsByUserClientParams{
		UserID:   uid,
		ClientID: clientID,
	})
}

// rowToRefreshSession converts a sqlc Session row to the domain type.
func rowToRefreshSession(row db.Session) oidc.RefreshSession {
	var label string
	if row.DeviceLabel != nil {
		label = *row.DeviceLabel
	}
	var expiresAt, revokedAt time.Time
	if row.ExpiresAt.Valid {
		expiresAt = row.ExpiresAt.Time
	}
	if row.RevokedAt.Valid {
		revokedAt = row.RevokedAt.Time
	}
	return oidc.RefreshSession{
		ID:          uuidToString(row.ID),
		Region:      row.Region,
		UserID:      uuidToString(row.UserID),
		ClientID:    row.ClientID,
		DeviceLabel: label,
		TokenHash:   row.RefreshTokenHash,
		ExpiresAt:   expiresAt,
		RevokedAt:   revokedAt,
	}
}

// isRevoked reports whether a db.Session row has been revoked.
func isRevoked(row db.Session) bool {
	return row.RevokedAt.Valid
}
