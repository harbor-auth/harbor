package clients

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor-auth/harbor/internal/gen/db"
)

// complianceUserQuerier is the narrow interface over *db.Queries that
// DBComplianceUserLoader needs. Production code passes *db.Queries; tests pass
// a small fake.
type complianceUserQuerier interface {
	GetUser(ctx context.Context, id pgtype.UUID) (db.User, error)
}

// DBComplianceUserLoader adapts the users table into the LoadUserForAudit
// method required by both identity.AuditUserLoader and
// mgmtapi.ComplianceUserLoader. It is the single place that converts a
// string UUID into a pgtype.UUID for the compliance and audit paths.
type DBComplianceUserLoader struct {
	q complianceUserQuerier
}

// NewDBComplianceUserLoader returns a loader backed by q. q is typically
// *db.Queries obtained from a pgx connection pool.
func NewDBComplianceUserLoader(q *db.Queries) *DBComplianceUserLoader {
	return &DBComplianceUserLoader{q: q}
}

// LoadUserForAudit implements both identity.AuditUserLoader and
// mgmtapi.ComplianceUserLoader. It resolves the user's region and wrapped DEK
// from the users table. The wrapped DEK is needed by the AuditRecorder to
// unwrap the per-user DEK before encrypting audit payloads; the region is
// needed for regional telemetry metering on the compliance endpoints.
func (l *DBComplianceUserLoader) LoadUserForAudit(ctx context.Context, userID string) (string, []byte, error) {
	id, err := parseUUID(userID)
	if err != nil {
		return "", nil, fmt.Errorf("clients: compliance: parse user ID %q: %w", userID, err)
	}
	user, err := l.q.GetUser(ctx, id)
	if err != nil {
		return "", nil, fmt.Errorf("clients: compliance: get user: %w", err)
	}
	return user.Region, user.DekWrapped, nil
}
