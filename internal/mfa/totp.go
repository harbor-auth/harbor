package mfa

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors returned by the MFA service and its stores. The mgmtapi and
// BFF layers map these to HTTP status codes with PII-free messages
// (docs/DESIGN.md §6.5) — a mismatched TOTP code and an unknown user both
// surface generically so the response never reveals which check failed.
var (
	// ErrFactorNotFound is returned when a lookup targets a factor (or a user's
	// factors) that does not exist.
	ErrFactorNotFound = errors.New("mfa: factor not found")
	// ErrInvalidCode is returned when a submitted TOTP or recovery code does not
	// match an active, unused factor. It is deliberately generic: callers must
	// not distinguish "wrong code" from "no factor" to an unauthenticated peer.
	ErrInvalidCode = errors.New("mfa: invalid code")
	// ErrAlreadyEnrolled is returned when a user who already has an active TOTP
	// factor attempts to enroll a second one. Re-enrollment requires disabling
	// the existing factor first, so a lost-device attacker cannot silently swap
	// in a new secret.
	ErrAlreadyEnrolled = errors.New("mfa: user already has an active TOTP factor")
	// ErrNotEnrolled is returned when a verification or activation is attempted
	// for a user who has no TOTP factor enrolled.
	ErrNotEnrolled = errors.New("mfa: user has no TOTP factor enrolled")
	// ErrCodeAlreadyUsed is returned when a recovery code that matches a stored
	// hash has already been burned — a replay attempt on a single-use code.
	ErrCodeAlreadyUsed = errors.New("mfa: recovery code has already been used")
)

// FactorType identifies the kind of MFA factor stored in mfa_factors.type. The
// two kinds share one table but differ in payload: a TOTP factor carries the
// envelope-encrypted shared secret; a recovery-code factor carries a bcrypt
// hash and is single-use.
type FactorType string

const (
	// FactorTypeTOTP is a time-based one-time-password authenticator secret
	// (RFC 6238), envelope-encrypted under the user's DEK.
	FactorTypeTOTP FactorType = "totp"
	// FactorTypeRecovery is a single-use bcrypt-hashed recovery code, burned on
	// first successful use.
	FactorTypeRecovery FactorType = "recovery_code"
)

// Factor is the domain view of a row in mfa_factors — metadata ONLY. It
// deliberately omits the encrypted secret and the recovery-code hash: those
// never leave the store layer, so a Factor is always safe to return from an API
// handler or log at debug level (docs/DESIGN.md §6.5).
type Factor struct {
	// ID is the factor's UUID (mfa_factors.id).
	ID string
	// UserID is the owning user's UUID (mfa_factors.user_id).
	UserID string
	// Region is the factor's home region; factors are region-pinned and never
	// cross-region replicated (mfa_factors.region, docs/DESIGN.md §10).
	Region string
	// Type is the factor kind (TOTP or recovery code).
	Type FactorType
	// Used reports whether a single-use factor (recovery code) has been burned.
	// Always false for an active TOTP factor.
	Used bool
	// CreatedAt is when the factor was enrolled (mfa_factors.created_at).
	CreatedAt time.Time
}

// EnrollResult is returned once, at enrollment time, and carries the only
// plaintext material the user will ever see. Nothing here is persisted in the
// clear: the TOTP secret is stored envelope-encrypted and the recovery codes
// are stored bcrypt-hashed. The caller MUST surface these to the user and then
// discard them — they cannot be recovered later.
type EnrollResult struct {
	// FactorID is the newly-created (pending) TOTP factor's UUID.
	FactorID string
	// Secret is the base32-encoded TOTP shared secret, for manual entry into an
	// authenticator app that cannot scan the QR code.
	Secret string
	// ProvisioningURI is the otpauth:// URI (RFC 6238 key URI format) the client
	// renders as a QR code for the authenticator app.
	ProvisioningURI string
	// RecoveryCodes are the freshly-generated single-use recovery codes, in
	// plaintext. They are shown to the user exactly once and stored only as
	// bcrypt hashes; each can be redeemed once via VerifyRecoveryCode.
	RecoveryCodes []string
}

// TOTPService is the MFA enrollment and step-up verification core. It owns no
// per-request state and performs no HTTP; the thin I/O layer lives in
// internal/mgmtapi (management endpoints) and the BFF step-up gate. Persistence
// and envelope encryption are delegated to the store, so this interface stays
// unit-testable without a database (docs/DESIGN.md §1.7).
//
// Enrollment is a two-step, confirm-before-activate flow: Enroll mints a
// PENDING secret + recovery codes, and Activate promotes it only after the user
// proves they can produce a valid code from it. This prevents a mis-scanned QR
// from locking the user out of their own account.
type TOTPService interface {
	// Enroll begins TOTP enrollment for a user: it generates a fresh TOTP secret
	// (envelope-encrypted under the user's DEK) plus a set of single-use
	// recovery codes, persists them, and returns the plaintext material for the
	// user to record. The factor is PENDING until confirmed via Activate.
	//
	// Returns ErrAlreadyEnrolled if the user already has an active TOTP factor.
	Enroll(ctx context.Context, userID string) (*EnrollResult, error)

	// Activate confirms a pending TOTP enrollment by verifying the user can
	// produce a valid code from the freshly-enrolled secret. On success the
	// factor becomes active and eligible for step-up challenges.
	//
	// Returns ErrNotEnrolled if there is no pending factor, or ErrInvalidCode if
	// the code does not match.
	Activate(ctx context.Context, userID, code string) error

	// Verify checks a TOTP code against the user's active TOTP factor for a
	// step-up challenge (the BFF step-up gate). It is read-only — a TOTP code is
	// reusable within its time window by design.
	//
	// Returns ErrNotEnrolled if the user has no active factor, or ErrInvalidCode
	// on mismatch.
	Verify(ctx context.Context, userID, code string) error

	// VerifyRecoveryCode checks a submitted recovery code against the user's
	// stored bcrypt hashes and, on the first match, BURNS it (marks the factor
	// used) so it can never be replayed. This is the fail-closed single-use
	// operation for lost-authenticator recovery.
	//
	// Returns ErrInvalidCode if no unused code matches.
	VerifyRecoveryCode(ctx context.Context, userID, code string) error

	// ListFactors returns the user's enrolled MFA factors as metadata only
	// (never secrets or hashes). Safe to surface to a management UI.
	ListFactors(ctx context.Context, userID string) ([]Factor, error)

	// Disable removes ALL of the user's MFA factors (the TOTP secret and every
	// recovery code). Used when the user turns off 2FA; after this the step-up
	// gate treats the user as MFA-disabled.
	Disable(ctx context.Context, userID string) error

	// HasMFA reports whether the user has an active TOTP factor enrolled. It is
	// the predicate the BFF step-up gate consults to decide whether a step-up
	// challenge is required before a sensitive action.
	HasMFA(ctx context.Context, userID string) (bool, error)
}
