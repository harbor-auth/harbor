package clients

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/identity"
)

// Recovery-related errors.
var (
	// ErrCodeNotFound is returned when the submitted code does not match any
	// stored code for the user.
	ErrCodeNotFound = errors.New("clients: recovery code not found")
	// ErrCodeAlreadyUsed is returned when a code was valid but has already been
	// consumed (race condition or replay attempt).
	ErrCodeAlreadyUsed = errors.New("clients: recovery code already used")
)

// recoveryQuerier is the narrow sqlc surface DBRecoveryStore needs.
type recoveryQuerier interface {
	GetRecoveryCodesByUser(ctx context.Context, userID pgtype.UUID) ([]db.RecoveryCode, error)
	ConsumeRecoveryCode(ctx context.Context, id pgtype.UUID) (db.RecoveryCode, error)
	CountUnusedCodes(ctx context.Context, userID pgtype.UUID) (int64, error)
	DeleteRecoveryCodesByUser(ctx context.Context, userID pgtype.UUID) error
	GetRecoveryAttempts(ctx context.Context, userID pgtype.UUID) (db.RecoveryAttempt, error)
	UpsertRecoveryAttempts(ctx context.Context, arg db.UpsertRecoveryAttemptsParams) (db.RecoveryAttempt, error)
	ResetRecoveryAttempts(ctx context.Context, userID pgtype.UUID) error
}

// recoveryCodeInserter handles batch insertion of recovery codes.
type recoveryCodeInserter interface {
	InsertRecoveryCodes(ctx context.Context, codes []db.InsertRecoveryCodesParams) (int64, error)
}

// DBRecoveryStore implements recovery code storage operations over the
// recovery_codes and recovery_attempts tables (docs/DESIGN.md §10).
// It handles atomic code consumption with lockout tracking.
type DBRecoveryStore struct {
	q        recoveryQuerier
	inserter recoveryCodeInserter
}

// NewDBRecoveryStore wraps a sqlc Queries for recovery code operations.
func NewDBRecoveryStore(q recoveryQuerier, inserter recoveryCodeInserter) *DBRecoveryStore {
	return &DBRecoveryStore{q: q, inserter: inserter}
}

// Compile-time proof that DBRecoveryStore implements identity.RecoveryStore.
var _ identity.RecoveryStore = (*DBRecoveryStore)(nil)

// StoreRecoveryCodes stores a batch of recovery codes for a user. It first
// deletes any existing codes (regeneration invalidates old codes).
func (s *DBRecoveryStore) StoreRecoveryCodes(ctx context.Context, userID string, codes []identity.RecoveryCode) error {
	uid, err := parseUUID(userID)
	if err != nil {
		return fmt.Errorf("recovery: parse user ID %q: %w", userID, err)
	}

	// Delete existing codes first (regeneration invalidates old codes).
	if err := s.q.DeleteRecoveryCodesByUser(ctx, uid); err != nil {
		return fmt.Errorf("recovery: delete existing codes: %w", err)
	}

	// Prepare batch insert params.
	now := time.Now()
	params := make([]db.InsertRecoveryCodesParams, 0, len(codes))
	for _, code := range codes {
		id := uuid.New()
		var idUUID pgtype.UUID
		if err := idUUID.Scan(id.String()); err != nil {
			return fmt.Errorf("recovery: generate code ID: %w", err)
		}
		var createdAt pgtype.Timestamptz
		if err := createdAt.Scan(now); err != nil {
			return fmt.Errorf("recovery: scan created_at: %w", err)
		}
		params = append(params, db.InsertRecoveryCodesParams{
			ID:        idUUID,
			UserID:    uid,
			CodeHash:  code.Hash,
			Salt:      code.Salt,
			CreatedAt: createdAt,
		})
	}

	if _, err := s.inserter.InsertRecoveryCodes(ctx, params); err != nil {
		return fmt.Errorf("recovery: insert codes: %w", err)
	}
	return nil
}

// GetLockoutState returns the current lockout state for a user.
func (s *DBRecoveryStore) GetLockoutState(ctx context.Context, userID string) (identity.LockoutState, error) {
	uid, err := parseUUID(userID)
	if err != nil {
		return identity.LockoutState{}, fmt.Errorf("recovery: parse user ID %q: %w", userID, err)
	}

	attempts, err := s.q.GetRecoveryAttempts(ctx, uid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// No record means no failed attempts yet.
			return identity.LockoutState{FailedCount: 0}, nil
		}
		return identity.LockoutState{}, fmt.Errorf("recovery: get attempts: %w", err)
	}

	state := identity.LockoutState{
		FailedCount: int(attempts.FailedCount),
	}
	if attempts.LockedUntil.Valid {
		state.LockedUntil = attempts.LockedUntil.Time
	}
	return state, nil
}

// RecordFailedAttempt increments the failed attempt counter and optionally
// sets a lockout time.
func (s *DBRecoveryStore) RecordFailedAttempt(ctx context.Context, userID string, newCount int, lockUntil *time.Time) error {
	uid, err := parseUUID(userID)
	if err != nil {
		return fmt.Errorf("recovery: parse user ID %q: %w", userID, err)
	}

	var lockedUntil pgtype.Timestamptz
	if lockUntil != nil {
		if err := lockedUntil.Scan(*lockUntil); err != nil {
			return fmt.Errorf("recovery: scan locked_until: %w", err)
		}
	}

	_, err = s.q.UpsertRecoveryAttempts(ctx, db.UpsertRecoveryAttemptsParams{
		UserID:      uid,
		FailedCount: int32(newCount),
		LockedUntil: lockedUntil,
	})
	if err != nil {
		return fmt.Errorf("recovery: upsert attempts: %w", err)
	}
	return nil
}

// ResetFailedAttempts clears the failed attempt counter after a successful recovery.
func (s *DBRecoveryStore) ResetFailedAttempts(ctx context.Context, userID string) error {
	uid, err := parseUUID(userID)
	if err != nil {
		return fmt.Errorf("recovery: parse user ID %q: %w", userID, err)
	}

	if err := s.q.ResetRecoveryAttempts(ctx, uid); err != nil {
		return fmt.Errorf("recovery: reset attempts: %w", err)
	}
	return nil
}

// FindAndConsumeCode finds a matching code for the user and atomically marks
// it as used. Returns the code ID on success, or an error if no matching
// unused code is found.
func (s *DBRecoveryStore) FindAndConsumeCode(ctx context.Context, userID, submittedCode string) (string, error) {
	uid, err := parseUUID(userID)
	if err != nil {
		return "", fmt.Errorf("recovery: parse user ID %q: %w", userID, err)
	}

	// Get all codes for the user.
	codes, err := s.q.GetRecoveryCodesByUser(ctx, uid)
	if err != nil {
		return "", fmt.Errorf("recovery: get codes: %w", err)
	}

	// Find a matching unused code.
	var matchingCodeID pgtype.UUID
	found := false
	for _, code := range codes {
		// Skip already-used codes.
		if code.UsedAt.Valid {
			continue
		}
		// Check if submitted code matches this code's hash.
		if identity.VerifyCode(submittedCode, code.CodeHash, code.Salt) {
			matchingCodeID = code.ID
			found = true
			break
		}
	}

	if !found {
		return "", ErrCodeNotFound
	}

	// Atomically consume the code (only if still unused).
	consumedCode, err := s.q.ConsumeRecoveryCode(ctx, matchingCodeID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Race condition: code was consumed between find and consume.
			return "", ErrCodeAlreadyUsed
		}
		return "", fmt.Errorf("recovery: consume code: %w", err)
	}

	return uuidToString(consumedCode.ID), nil
}

// CountUnusedCodes returns the number of unused recovery codes for a user.
func (s *DBRecoveryStore) CountUnusedCodes(ctx context.Context, userID string) (int, error) {
	uid, err := parseUUID(userID)
	if err != nil {
		return 0, fmt.Errorf("recovery: parse user ID %q: %w", userID, err)
	}

	count, err := s.q.CountUnusedCodes(ctx, uid)
	if err != nil {
		return 0, fmt.Errorf("recovery: count unused codes: %w", err)
	}
	return int(count), nil
}
