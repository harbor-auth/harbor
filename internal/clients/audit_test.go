package clients

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor-auth/harbor/internal/gen/db"
)

// fakeAuditQuerier is an in-memory auditQuerier fake for unit tests.
type fakeAuditQuerier struct {
	rows  []db.AuditEvent
	dbErr error // if non-nil, every call returns this
	// captured args from the last call
	capturedUserID pgtype.UUID
	capturedLimit  int32
	capturedOffset int32
}

func (f *fakeAuditQuerier) ListAuditEventsByUserWithPayload(_ context.Context, arg db.ListAuditEventsByUserWithPayloadParams) ([]db.AuditEvent, error) {
	f.capturedUserID = arg.UserID
	f.capturedLimit = arg.Limit
	f.capturedOffset = arg.Offset
	if f.dbErr != nil {
		return nil, f.dbErr
	}
	return f.rows, nil
}

func TestDBAuditStoreListEvents(t *testing.T) {
	occurredAt := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	clientID := "rp-1"
	q := &fakeAuditQuerier{
		rows: []db.AuditEvent{
			{
				ID:               pgUUID("c0000000-0000-0000-0000-000000000001"),
				Region:           "eu-1",
				UserID:           pgUUID(testUserID),
				EventType:        "token.issued",
				ClientID:         &clientID,
				OccurredAt:       pgtype.Timestamptz{Time: occurredAt, Valid: true},
				PayloadEncrypted: []byte("ciphertext"),
			},
			{
				ID:        pgUUID("c0000000-0000-0000-0000-000000000002"),
				Region:    "eu-1",
				UserID:    pgUUID(testUserID),
				EventType: "auth.login",
				ClientID:  nil,
				OccurredAt: pgtype.Timestamptz{Time: occurredAt.Add(-time.Hour), Valid: true},
				// No payload — pre-migration row.
			},
		},
	}
	s := &DBAuditStore{q: q}

	events, err := s.ListAuditEvents(context.Background(), testUserID, 50, 0)
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}

	// First event — with encrypted payload and client ID.
	ev := events[0]
	if ev.ID != "c0000000-0000-0000-0000-000000000001" {
		t.Errorf("events[0].ID = %q, want c0000000-...-000001", ev.ID)
	}
	if ev.EventType != "token.issued" {
		t.Errorf("events[0].EventType = %q, want token.issued", ev.EventType)
	}
	if ev.ClientID == nil || *ev.ClientID != clientID {
		t.Errorf("events[0].ClientID = %v, want %q", ev.ClientID, clientID)
	}
	if !ev.OccurredAt.Equal(occurredAt) {
		t.Errorf("events[0].OccurredAt = %v, want %v", ev.OccurredAt, occurredAt)
	}
	if ev.Region != "eu-1" {
		t.Errorf("events[0].Region = %q, want eu-1", ev.Region)
	}
	if string(ev.PayloadEncrypted) != "ciphertext" {
		t.Errorf("events[0].PayloadEncrypted = %q, want ciphertext", ev.PayloadEncrypted)
	}

	// Second event — no payload, no client ID (pre-migration row).
	ev2 := events[1]
	if ev2.EventType != "auth.login" {
		t.Errorf("events[1].EventType = %q, want auth.login", ev2.EventType)
	}
	if ev2.ClientID != nil {
		t.Errorf("events[1].ClientID = %v, want nil", ev2.ClientID)
	}
	if len(ev2.PayloadEncrypted) != 0 {
		t.Errorf("events[1].PayloadEncrypted should be empty for pre-migration row")
	}
}

func TestDBAuditStoreForwardsPaginationParams(t *testing.T) {
	q := &fakeAuditQuerier{}
	s := &DBAuditStore{q: q}

	_, err := s.ListAuditEvents(context.Background(), testUserID, 25, 75)
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	if q.capturedLimit != 25 {
		t.Errorf("limit forwarded = %d, want 25", q.capturedLimit)
	}
	if q.capturedOffset != 75 {
		t.Errorf("offset forwarded = %d, want 75", q.capturedOffset)
	}
	// Verify the userID was correctly parsed and forwarded.
	want := pgUUID(testUserID)
	if q.capturedUserID != want {
		t.Errorf("userID forwarded = %v, want %v", q.capturedUserID, want)
	}
}

func TestDBAuditStoreEmptyResult(t *testing.T) {
	q := &fakeAuditQuerier{rows: nil}
	s := &DBAuditStore{q: q}

	events, err := s.ListAuditEvents(context.Background(), testUserID, 50, 0)
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("got %d events, want 0", len(events))
	}
}

func TestDBAuditStoreDBError(t *testing.T) {
	q := &fakeAuditQuerier{dbErr: errors.New("db timeout")}
	s := &DBAuditStore{q: q}

	_, err := s.ListAuditEvents(context.Background(), testUserID, 50, 0)
	if err == nil {
		t.Error("expected error propagation from DB error")
	}
}

func TestDBAuditStoreInvalidUUID(t *testing.T) {
	q := &fakeAuditQuerier{}
	s := &DBAuditStore{q: q}

	_, err := s.ListAuditEvents(context.Background(), "not-a-valid-uuid", 50, 0)
	if err == nil {
		t.Error("expected error for invalid UUID")
	}
}

func TestDBAuditStoreImplementsAuditStore(t *testing.T) {
	// Compile-time interface satisfaction proof. DBAuditStore cannot satisfy
	// mgmtapi.AuditStore here directly (import cycle), but the structural
	// check is enforced in cmd/harbor-mgmt/main.go which imports both.
	// This test verifies the concrete method signature matches expectations.
	var s interface{ ListAuditEvents(context.Context, string, int, int) ([]RawAuditEvent, error) }
	s = &DBAuditStore{q: &fakeAuditQuerier{}}
	_ = s
}
