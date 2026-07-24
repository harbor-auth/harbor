package clients

import (
	"context"
	"fmt"
	"time"

	"github.com/harbor-auth/harbor/internal/gen/db"
)

// RawAuditEvent is the pre-decryption DB row returned by DBAuditStore. The
// PayloadEncrypted field is the ciphertext under the user's DEK; it is
// nil/empty for rows written before migration 0013_audit_events.
//
// Defined here (in clients) rather than in mgmtapi so that DBAuditStore can
// return this type without importing mgmtapi — which would form a cycle because
// mgmtapi/register.go already imports clients. mgmtapi aliases this type as
// mgmtapi.RawAuditEvent so all existing handler and test code is unchanged.
type RawAuditEvent struct {
	ID               string
	EventType        string
	ClientID         *string
	OccurredAt       time.Time
	Region           string
	PayloadEncrypted []byte
}

// auditQuerier is the narrow interface over *db.Queries that DBAuditStore
// needs. Production code passes *db.Queries; tests pass a small fake.
type auditQuerier interface {
	ListAuditEventsByUserWithPayload(ctx context.Context, arg db.ListAuditEventsByUserWithPayloadParams) ([]db.AuditEvent, error)
}

// DBAuditStore adapts the audit_events table into the AuditStore interface
// required by mgmtapi.AuditTrailDeps (DESIGN §10, §11.6). It is the single
// place that converts a string UUID into a pgtype.UUID for the audit read path.
type DBAuditStore struct {
	q auditQuerier
}

// NewDBAuditStore returns an AuditStore backed by q. q is typically
// *db.Queries obtained from a pgx connection pool.
func NewDBAuditStore(q *db.Queries) *DBAuditStore {
	return &DBAuditStore{q: q}
}

// ListAuditEvents implements mgmtapi.AuditStore. It returns the user's audit
// events newest-first with limit/offset pagination. The payload_encrypted
// column is included so the caller can decrypt under the user's DEK.
func (s *DBAuditStore) ListAuditEvents(ctx context.Context, userID string, limit, offset int) ([]RawAuditEvent, error) {
	id, err := parseUUID(userID)
	if err != nil {
		return nil, fmt.Errorf("clients: audit: parse user ID %q: %w", userID, err)
	}
	rows, err := s.q.ListAuditEventsByUserWithPayload(ctx, db.ListAuditEventsByUserWithPayloadParams{
		UserID: id,
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		return nil, fmt.Errorf("clients: audit: list events: %w", err)
	}
	out := make([]RawAuditEvent, len(rows))
	for i, row := range rows {
		out[i] = RawAuditEvent{
			ID:               uuidToString(row.ID),
			EventType:        row.EventType,
			ClientID:         row.ClientID,
			OccurredAt:       row.OccurredAt.Time,
			Region:           row.Region,
			PayloadEncrypted: row.PayloadEncrypted,
		}
	}
	return out, nil
}
