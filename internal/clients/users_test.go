package clients

import (
	"context"
	"errors"
	"testing"

	"github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/identity"
)

// fakeUserQuerier is an in-memory userQuerier fake for unit tests.
type fakeUserQuerier struct {
	stored map[string]db.CreateUserParams // keyed by UUID string
	dbErr  error                          // if non-nil, every call returns this
}

func newFakeUserQuerier() *fakeUserQuerier {
	return &fakeUserQuerier{stored: make(map[string]db.CreateUserParams)}
}

func (f *fakeUserQuerier) CreateUser(_ context.Context, arg db.CreateUserParams) (db.User, error) {
	if f.dbErr != nil {
		return db.User{}, f.dbErr
	}
	f.stored[uuidToString(arg.ID)] = arg
	return db.User{
		ID:             arg.ID,
		Region:         arg.Region,
		Status:         arg.Status,
		DekWrapped:     arg.DekWrapped,
		PairwiseSecret: arg.PairwiseSecret,
	}, nil
}

func TestDBUserPersisterPersistsUser(t *testing.T) {
	q := newFakeUserQuerier()
	p := NewDBUserPersister(q)

	rec := identity.UserRecord{
		ID:               testUserID,
		Region:           "eu-1",
		DekWrapped:       []byte("wrapped-dek"),
		PairwiseSecret:   []byte("encrypted-secret"),
		RecoveryRequired: true,
	}
	if err := p.PersistUser(context.Background(), rec); err != nil {
		t.Fatalf("PersistUser: %v", err)
	}

	stored, ok := q.stored[testUserID]
	if !ok {
		t.Fatal("expected user to be stored")
	}
	if stored.Region != "eu-1" {
		t.Errorf("Region: got %q, want eu-1", stored.Region)
	}
	// Enrollment writes a PENDING user (design decision 3, §11.1); the account
	// is flipped to "active" atomically with the first passkey registration.
	if stored.Status != "pending" {
		t.Errorf("Status: got %q, want pending", stored.Status)
	}
	// Sealed secrets must be forwarded verbatim — no re-encoding, no truncation.
	if string(stored.DekWrapped) != "wrapped-dek" {
		t.Errorf("DekWrapped not preserved: got %q", stored.DekWrapped)
	}
	if string(stored.PairwiseSecret) != "encrypted-secret" {
		t.Errorf("PairwiseSecret not preserved: got %q", stored.PairwiseSecret)
	}
}

func TestDBUserPersisterDBError(t *testing.T) {
	q := &fakeUserQuerier{stored: make(map[string]db.CreateUserParams), dbErr: errors.New("db insert failed")}
	p := NewDBUserPersister(q)
	err := p.PersistUser(context.Background(), identity.UserRecord{
		ID:               testUserID,
		Region:           "eu-1",
		RecoveryRequired: true,
	})
	if err == nil {
		t.Error("expected error propagation from DB error")
	}
}

func TestDBUserPersisterInvalidUUID(t *testing.T) {
	p := NewDBUserPersister(newFakeUserQuerier())
	err := p.PersistUser(context.Background(), identity.UserRecord{
		ID:               "not-a-valid-uuid",
		Region:           "eu-1",
		RecoveryRequired: true,
	})
	if err == nil {
		t.Error("expected error for invalid UUID")
	}
}

// TestDBUserPersisterRejectsRecoveryNotRequired verifies the persister fails
// closed: it must never create a user that has already bypassed recovery setup
// (REQ-005). The CreateUser query cannot express recovery_required=false, so a
// record claiming so is a programming error and must be rejected before any DB
// write.
func TestDBUserPersisterRejectsRecoveryNotRequired(t *testing.T) {
	q := newFakeUserQuerier()
	p := NewDBUserPersister(q)
	err := p.PersistUser(context.Background(), identity.UserRecord{
		ID:               testUserID,
		Region:           "eu-1",
		RecoveryRequired: false,
	})
	if err == nil {
		t.Fatal("expected error when RecoveryRequired is false")
	}
	if len(q.stored) != 0 {
		t.Fatal("no DB write should occur when RecoveryRequired is false")
	}
}

func TestDBUserPersisterImplementsInterface(t *testing.T) {
	var _ identity.UserPersister = (*DBUserPersister)(nil)
}
