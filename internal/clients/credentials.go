package clients

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor-auth/harbor/internal/gen/db"
)

// ErrCredentialNotFound is returned by DashboardCredentialStore operations when
// the requested credential does not exist or does not belong to the caller.
// Handlers map this to HTTP 404.
var ErrCredentialNotFound = errors.New("clients: credential not found")

// DashboardCredential is the dashboard-facing view of a registered authenticator
// (passkey). It carries only the fields the Sessions & Devices view needs;
// raw cryptographic material (pubkey, aaguid, password_hash) is intentionally
// omitted — the dashboard is a display/revoke surface, not a crypto path.
type DashboardCredential struct {
	ID        string
	UserID    string
	Type      string
	CreatedAt time.Time
}

// DashboardCredentialStore is the narrow read/delete interface the dashboard
// handler uses to list and revoke a caller's registered authenticators.
// Strictly caller-scoped: ListCredentialsByUser and DeleteCredential both
// enforce that only the authenticated user's own credentials are accessible.
type DashboardCredentialStore interface {
	// ListCredentialsByUser returns all credentials registered by userID,
	// ordered by creation time descending.
	ListCredentialsByUser(ctx context.Context, userID string) ([]DashboardCredential, error)
	// DeleteCredential removes the credential identified by credentialID.
	// It returns an error if the credential does not belong to userID, so
	// the caller cannot revoke another user's authenticator.
	DeleteCredential(ctx context.Context, credentialID, userID string) error
}

// credentialQuerier is the narrow sqlc surface DBDashboardCredentialStore needs.
type credentialQuerier interface {
	ListCredentialsByUser(ctx context.Context, userID pgtype.UUID) ([]db.Credential, error)
	GetCredential(ctx context.Context, id pgtype.UUID) (db.Credential, error)
	DeleteCredential(ctx context.Context, id pgtype.UUID) error
}

// DBDashboardCredentialStore implements DashboardCredentialStore over the
// credentials table via sqlc. All operations are caller-scoped: callers must
// supply the authenticated userID so cross-user operations are refused.
type DBDashboardCredentialStore struct {
	q credentialQuerier
}

// NewDBDashboardCredentialStore returns a DashboardCredentialStore backed by q.
func NewDBDashboardCredentialStore(q credentialQuerier) *DBDashboardCredentialStore {
	return &DBDashboardCredentialStore{q: q}
}

// Compile-time proof that DBDashboardCredentialStore implements DashboardCredentialStore.
var _ DashboardCredentialStore = (*DBDashboardCredentialStore)(nil)

// ListCredentialsByUser implements DashboardCredentialStore.
func (s *DBDashboardCredentialStore) ListCredentialsByUser(ctx context.Context, userID string) ([]DashboardCredential, error) {
	var uid pgtype.UUID
	if err := uid.Scan(userID); err != nil {
		return nil, fmt.Errorf("clients: credentials: parse user ID %q: %w", userID, err)
	}
	rows, err := s.q.ListCredentialsByUser(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("clients: credentials: list by user: %w", err)
	}
	out := make([]DashboardCredential, 0, len(rows))
	for _, row := range rows {
		out = append(out, rowToDashboardCredential(row))
	}
	return out, nil
}

// DeleteCredential implements DashboardCredentialStore. It first verifies the
// credential belongs to userID (cross-user guard, fails closed) before deleting.
func (s *DBDashboardCredentialStore) DeleteCredential(ctx context.Context, credentialID, userID string) error {
	var cid pgtype.UUID
	if err := cid.Scan(credentialID); err != nil {
		return fmt.Errorf("clients: credentials: parse credential ID %q: %w", credentialID, err)
	}
	var uid pgtype.UUID
	if err := uid.Scan(userID); err != nil {
		return fmt.Errorf("clients: credentials: parse user ID %q: %w", userID, err)
	}
	row, err := s.q.GetCredential(ctx, cid)
	if err != nil {
		// Return a generic not-found rather than leaking whether the credential
		// exists at all (DESIGN §6.5 — PII-free error messages).
		return ErrCredentialNotFound
	}
	// Cross-user guard: refuse to delete a credential that belongs to a
	// different user. Fail closed — never trust the caller alone.
	if row.UserID.Bytes != uid.Bytes {
		return ErrCredentialNotFound
	}
	if err := s.q.DeleteCredential(ctx, cid); err != nil {
		return fmt.Errorf("clients: credentials: delete: %w", err)
	}
	return nil
}

// rowToDashboardCredential converts a sqlc Credential row to the dashboard
// domain type, omitting raw cryptographic material.
func rowToDashboardCredential(row db.Credential) DashboardCredential {
	var createdAt time.Time
	if row.CreatedAt.Valid {
		createdAt = row.CreatedAt.Time
	}
	return DashboardCredential{
		ID:        uuidToString(row.ID),
		UserID:    uuidToString(row.UserID),
		Type:      row.Type,
		CreatedAt: createdAt,
	}
}
