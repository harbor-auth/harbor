package clients

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor/harbor/internal/gen/db"
	"github.com/harbor/harbor/internal/identity"
)

// fakeRecoveryQuerier is a test double for recoveryQuerier.
type fakeRecoveryQuerier struct {
	codes            []db.RecoveryCode
	attempts         *db.RecoveryAttempt
	consumedCodeID   pgtype.UUID
	consumeErr       error
	getCodesErr      error
	getAttemptsErr   error
	upsertAttemptsErr error
	resetAttemptsErr error
	deleteCodesErr   error
}

func (f *fakeRecoveryQuerier) GetRecoveryCodesByUser(_ context.Context, _ pgtype.UUID) ([]db.RecoveryCode, error) {
	if f.getCodesErr != nil {
		return nil, f.getCodesErr
	}
	return f.codes, nil
}

func (f *fakeRecoveryQuerier) ConsumeRecoveryCode(_ context.Context, id pgtype.UUID) (db.RecoveryCode, error) {
	if f.consumeErr != nil {
		return db.RecoveryCode{}, f.consumeErr
	}
	f.consumedCodeID = id
	for _, code := range f.codes {
		if code.ID == id {
			code.UsedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
			return code, nil
		}
	}
	return db.RecoveryCode{}, pgx.ErrNoRows
}

func (f *fakeRecoveryQuerier) CountUnusedCodes(_ context.Context, _ pgtype.UUID) (int64, error) {
	var count int64
	for _, code := range f.codes {
		if !code.UsedAt.Valid {
			count++
		}
	}
	return count, nil
}

func (f *fakeRecoveryQuerier) DeleteRecoveryCodesByUser(_ context.Context, _ pgtype.UUID) error {
	if f.deleteCodesErr != nil {
		return f.deleteCodesErr
	}
	f.codes = nil
	return nil
}

func (f *fakeRecoveryQuerier) GetRecoveryAttempts(_ context.Context, _ pgtype.UUID) (db.RecoveryAttempt, error) {
	if f.getAttemptsErr != nil {
		return db.RecoveryAttempt{}, f.getAttemptsErr
	}
	if f.attempts == nil {
		return db.RecoveryAttempt{}, pgx.ErrNoRows
	}
	return *f.attempts, nil
}

func (f *fakeRecoveryQuerier) UpsertRecoveryAttempts(_ context.Context, arg db.UpsertRecoveryAttemptsParams) (db.RecoveryAttempt, error) {
	if f.upsertAttemptsErr != nil {
		return db.RecoveryAttempt{}, f.upsertAttemptsErr
	}
	f.attempts = &db.RecoveryAttempt{
		UserID:      arg.UserID,
		FailedCount: arg.FailedCount,
		LockedUntil: arg.LockedUntil,
	}
	return *f.attempts, nil
}

func (f *fakeRecoveryQuerier) ResetRecoveryAttempts(_ context.Context, _ pgtype.UUID) error {
	if f.resetAttemptsErr != nil {
		return f.resetAttemptsErr
	}
	f.attempts = nil
	return nil
}

// fakeInserter is a test double for recoveryCodeInserter.
type fakeInserter struct {
	insertedCodes []db.InsertRecoveryCodesParams
	insertErr     error
}

func (f *fakeInserter) InsertRecoveryCodes(_ context.Context, codes []db.InsertRecoveryCodesParams) (int64, error) {
	if f.insertErr != nil {
		return 0, f.insertErr
	}
	f.insertedCodes = codes
	return int64(len(codes)), nil
}

func TestDBRecoveryStore_GetLockoutState_NoRecord(t *testing.T) {
	q := &fakeRecoveryQuerier{getAttemptsErr: pgx.ErrNoRows}
	store := NewDBRecoveryStore(q, nil)

	state, err := store.GetLockoutState(context.Background(), "550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatalf("GetLockoutState: %v", err)
	}
	if state.FailedCount != 0 {
		t.Errorf("FailedCount = %d, want 0", state.FailedCount)
	}
	if !state.LockedUntil.IsZero() {
		t.Errorf("LockedUntil = %v, want zero", state.LockedUntil)
	}
}

func TestDBRecoveryStore_GetLockoutState_WithRecord(t *testing.T) {
	lockTime := time.Now().Add(10 * time.Minute)
	q := &fakeRecoveryQuerier{
		attempts: &db.RecoveryAttempt{
			FailedCount: 3,
			LockedUntil: pgtype.Timestamptz{Time: lockTime, Valid: true},
		},
	}
	store := NewDBRecoveryStore(q, nil)

	state, err := store.GetLockoutState(context.Background(), "550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatalf("GetLockoutState: %v", err)
	}
	if state.FailedCount != 3 {
		t.Errorf("FailedCount = %d, want 3", state.FailedCount)
	}
	if !state.LockedUntil.Equal(lockTime) {
		t.Errorf("LockedUntil = %v, want %v", state.LockedUntil, lockTime)
	}
}

func TestDBRecoveryStore_RecordFailedAttempt(t *testing.T) {
	q := &fakeRecoveryQuerier{}
	store := NewDBRecoveryStore(q, nil)

	lockTime := time.Now().Add(15 * time.Minute)
	err := store.RecordFailedAttempt(context.Background(), "550e8400-e29b-41d4-a716-446655440000", 5, &lockTime)
	if err != nil {
		t.Fatalf("RecordFailedAttempt: %v", err)
	}

	if q.attempts == nil {
		t.Fatal("attempts not recorded")
	}
	if q.attempts.FailedCount != 5 {
		t.Errorf("FailedCount = %d, want 5", q.attempts.FailedCount)
	}
}

func TestDBRecoveryStore_ResetFailedAttempts(t *testing.T) {
	q := &fakeRecoveryQuerier{
		attempts: &db.RecoveryAttempt{FailedCount: 3},
	}
	store := NewDBRecoveryStore(q, nil)

	err := store.ResetFailedAttempts(context.Background(), "550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatalf("ResetFailedAttempts: %v", err)
	}

	if q.attempts != nil {
		t.Error("attempts should be nil after reset")
	}
}

func TestDBRecoveryStore_FindAndConsumeCode_Success(t *testing.T) {
	// Generate a real code so we have valid hash/salt.
	mgr := identity.NewRecoveryManager()
	codes, err := mgr.GenerateCodes(1)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	code := codes[0]

	var codeID pgtype.UUID
	_ = codeID.Scan("550e8400-e29b-41d4-a716-446655440001")

	q := &fakeRecoveryQuerier{
		codes: []db.RecoveryCode{
			{
				ID:       codeID,
				CodeHash: code.Hash,
				Salt:     code.Salt,
				UsedAt:   pgtype.Timestamptz{Valid: false},
			},
		},
	}
	store := NewDBRecoveryStore(q, nil)

	consumedID, err := store.FindAndConsumeCode(context.Background(), "550e8400-e29b-41d4-a716-446655440000", code.Plaintext)
	if err != nil {
		t.Fatalf("FindAndConsumeCode: %v", err)
	}
	if consumedID == "" {
		t.Error("consumedID should not be empty")
	}
}

func TestDBRecoveryStore_FindAndConsumeCode_NotFound(t *testing.T) {
	q := &fakeRecoveryQuerier{codes: []db.RecoveryCode{}}
	store := NewDBRecoveryStore(q, nil)

	_, err := store.FindAndConsumeCode(context.Background(), "550e8400-e29b-41d4-a716-446655440000", "WRONG-CODE")
	if !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("expected ErrCodeNotFound, got %v", err)
	}
}

func TestDBRecoveryStore_FindAndConsumeCode_AlreadyUsed(t *testing.T) {
	// Generate a real code so we have valid hash/salt.
	mgr := identity.NewRecoveryManager()
	codes, err := mgr.GenerateCodes(1)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}
	code := codes[0]

	var codeID pgtype.UUID
	_ = codeID.Scan("550e8400-e29b-41d4-a716-446655440001")

	q := &fakeRecoveryQuerier{
		codes: []db.RecoveryCode{
			{
				ID:       codeID,
				CodeHash: code.Hash,
				Salt:     code.Salt,
				UsedAt:   pgtype.Timestamptz{Time: time.Now(), Valid: true},
			},
		},
	}
	store := NewDBRecoveryStore(q, nil)

	_, err = store.FindAndConsumeCode(context.Background(), "550e8400-e29b-41d4-a716-446655440000", code.Plaintext)
	if !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("expected ErrCodeNotFound for used code, got %v", err)
	}
}

func TestDBRecoveryStore_CountUnusedCodes(t *testing.T) {
	q := &fakeRecoveryQuerier{
		codes: []db.RecoveryCode{
			{UsedAt: pgtype.Timestamptz{Valid: false}},
			{UsedAt: pgtype.Timestamptz{Valid: false}},
			{UsedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}},
		},
	}
	store := NewDBRecoveryStore(q, nil)

	count, err := store.CountUnusedCodes(context.Background(), "550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatalf("CountUnusedCodes: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
}

func TestDBRecoveryStore_StoreRecoveryCodes(t *testing.T) {
	q := &fakeRecoveryQuerier{}
	inserter := &fakeInserter{}
	store := NewDBRecoveryStore(q, inserter)

	mgr := identity.NewRecoveryManager()
	codes, err := mgr.GenerateCodes(3)
	if err != nil {
		t.Fatalf("GenerateCodes: %v", err)
	}

	err = store.StoreRecoveryCodes(context.Background(), "550e8400-e29b-41d4-a716-446655440000", codes)
	if err != nil {
		t.Fatalf("StoreRecoveryCodes: %v", err)
	}

	if len(inserter.insertedCodes) != 3 {
		t.Errorf("inserted %d codes, want 3", len(inserter.insertedCodes))
	}
}
