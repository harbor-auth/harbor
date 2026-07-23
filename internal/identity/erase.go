package identity

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/jackc/pgx/v5/pgtype"
)

// EraseStore is the narrow write interface Eraser needs from the DB layer.
// All four operations are satisfied by *db.Queries.
type EraseStore interface {
	// EraseUserDEK atomically overwrites dek_wrapped with empty bytes and sets
	// status=erased. This is the crypto-shred operation.
	EraseUserDEK(ctx context.Context, id pgtype.UUID) error

	// DeleteRecoveryCodesByUser removes all recovery code hashes for the user.
	// Hashes are deleted on erase so no offline brute-force is possible.
	DeleteRecoveryCodesByUser(ctx context.Context, userID pgtype.UUID) error

	// RevokeSessionsByUser revokes every active session for the user,
	// ensuring no existing token can authenticate after erasure.
	RevokeSessionsByUser(ctx context.Context, userID pgtype.UUID) error
}

// EraseUserLoader loads the minimal user row needed to emit the pre-shred
// audit event (region + dek_wrapped). Satisfied by *db.Queries.
type EraseUserLoader interface {
	GetUser(ctx context.Context, id pgtype.UUID) (db.User, error)
}

// Eraser orchestrates the irreversible DSAR erasure lifecycle:
//  1. Load the user and capture region (verifies existence; DEK is live).
//  2. Emit compliance.erase_requested synchronously (DEK still valid; fail-closed).
//  3. Atomically crypto-shred the account (EraseUserDEK — point of no return).
//  4. Delete recovery code hashes.
//  5. Revoke all active sessions.
//  6. Emit compliance.erase_completed without payload (best-effort; DEK gone).
//
// The audit-before-shred ordering is mandatory: it ensures the decision is
// recorded while decryption is still possible. After EraseUserDEK the wrapped
// DEK is empty bytes, making all envelope-encrypted PII permanently
// unrecoverable without touching individual rows.
type Eraser struct {
	users    EraseUserLoader
	store    EraseStore
	recorder *AuditRecorder
	logger   *slog.Logger
}

// NewEraser constructs an Eraser. All arguments must be non-nil except logger
// (nil falls back to slog.Default).
func NewEraser(users EraseUserLoader, store EraseStore, recorder *AuditRecorder, logger *slog.Logger) *Eraser {
	if logger == nil {
		logger = slog.Default()
	}
	return &Eraser{
		users:    users,
		store:    store,
		recorder: recorder,
		logger:   logger,
	}
}

// Erase irreversibly crypto-shreds the account identified by userID.
// It is fail-closed: any error at steps 1–5 returns a non-nil error.
// Step 6 (erase_completed) is best-effort: a failure is logged but not
// propagated, because the irreversible shred at step 3 has already succeeded.
//
// Ordering invariant (mandatory):
//   - compliance.erase_requested is recorded synchronously BEFORE the DEK
//     is destroyed (step 2 before step 3).
//   - compliance.erase_completed is written WITHOUT a payload after the shred,
//     using RecordNoPayload so no DEK is required (step 6).
func (e *Eraser) Erase(ctx context.Context, userID string) error {
	userUUID, err := parseAuditUUID(userID)
	if err != nil {
		return fmt.Errorf("identity: erase: parse user ID: %w", err)
	}

	// Step 1 — load the user to confirm they exist and to capture region.
	// Region is needed for the erase_completed write after the DEK is gone.
	user, err := e.users.GetUser(ctx, userUUID)
	if err != nil {
		return fmt.Errorf("identity: erase: load user: %w", err)
	}
	region := user.Region

	// Step 2 — emit compliance.erase_requested synchronously BEFORE the shred.
	// The DEK is still valid; Record can unwrap + encrypt the (nil) detail.
	// Fail-closed: if this write fails, the shred does NOT proceed.
	if err := e.recorder.Record(ctx, userID, EventComplianceEraseRequested, nil, nil); err != nil {
		return fmt.Errorf("identity: erase: record erase_requested event: %w", err)
	}

	// Step 3 — atomically overwrite dek_wrapped with empty bytes and set
	// status=erased. This is the point of no return: all envelope-encrypted PII
	// is permanently unrecoverable from this moment on.
	if err := e.store.EraseUserDEK(ctx, userUUID); err != nil {
		return fmt.Errorf("identity: erase: crypto-shred DEK: %w", err)
	}

	// Step 4 — delete recovery code hashes. Hash deletion removes the offline
	// brute-force surface (the DEK is gone but hashes would persist otherwise).
	if err := e.store.DeleteRecoveryCodesByUser(ctx, userUUID); err != nil {
		return fmt.Errorf("identity: erase: delete recovery codes: %w", err)
	}

	// Step 5 — revoke all active sessions so any in-flight refresh tokens fail
	// immediately at the next use.
	if err := e.store.RevokeSessionsByUser(ctx, userUUID); err != nil {
		return fmt.Errorf("identity: erase: revoke sessions: %w", err)
	}

	// Step 6 — emit compliance.erase_completed WITHOUT a payload (the DEK is
	// gone; RecordNoPayload writes event_type + region + timestamp in the clear,
	// the exact pseudonymous survival set the design intends). Best-effort: a
	// failure here is logged but must not make the caller believe the erasure
	// failed — the irreversible shred in step 3 has already succeeded.
	if err := e.recorder.RecordNoPayload(ctx, userID, region, EventComplianceEraseCompleted, nil); err != nil {
		e.logger.WarnContext(ctx, "identity: erase: record erase_completed failed (best-effort)",
			"error", err)
	}

	return nil
}
