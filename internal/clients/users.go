package clients

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor/harbor/internal/gen/db"
	"github.com/harbor/harbor/internal/identity"
)

// userQuerier is the narrow interface over *db.Queries that DBUserPersister
// needs. Production code passes *db.Queries; tests pass a small fake.
type userQuerier interface {
	CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error)
}

// DBUserPersister implements identity.UserPersister by writing UserRecords to
// the users table (docs/DESIGN.md §10). The sealed dek_wrapped and
// pairwise_secret arrive pre-encrypted from the Enroller — this layer never
// sees or handles plaintext secrets (§4.4, §7.3).
type DBUserPersister struct {
	q userQuerier
}

// Compile-time proof that DBUserPersister implements identity.UserPersister.
var _ identity.UserPersister = (*DBUserPersister)(nil)

// NewDBUserPersister returns a UserPersister backed by q. q is typically
// *db.Queries obtained from a pgx connection pool.
func NewDBUserPersister(q userQuerier) *DBUserPersister {
	return &DBUserPersister{q: q}
}

// PersistUser implements identity.UserPersister. It writes the sealed
// enrollment record to the users table. The caller (identity.Enroller) has
// already encrypted dek_wrapped and pairwise_secret; this method only
// forwards the opaque bytes — no secret material is inspected or logged here.
//
// recovery_required (REQ-005) is enforced by the users table's NOT NULL
// DEFAULT true (migration 0006): every enrollment INSERT records
// recovery_required=true. Because the CreateUser query intentionally does not
// expose that column, we fail closed if a caller ever hands us a record that
// claims recovery is NOT required — enrollment must never create a user who
// has already bypassed recovery setup.
func (p *DBUserPersister) PersistUser(ctx context.Context, r identity.UserRecord) error {
	if !r.RecoveryRequired {
		return fmt.Errorf("clients: PersistUser: enrollment must set recovery_required=true (REQ-005)")
	}
	var id pgtype.UUID
	if err := id.Scan(r.ID); err != nil {
		return fmt.Errorf("clients: PersistUser: invalid user ID %q: %w", r.ID, err)
	}
	_, err := p.q.CreateUser(ctx, db.CreateUserParams{
		ID:             id,
		Region:         r.Region,
		Status:         "active",
		DekWrapped:     r.DekWrapped,
		PairwiseSecret: r.PairwiseSecret,
	})
	if err != nil {
		return fmt.Errorf("clients: PersistUser: %w", err)
	}
	return nil
}
