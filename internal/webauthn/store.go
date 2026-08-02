package webauthn

import (
	"context"
	"errors"
	"fmt"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// Sentinel errors from the stores. Handlers map these to HTTP status codes
// (handlers.go) with PII-free messages (docs/DESIGN.md §6.5).
var (
	ErrUserNotFound    = errors.New("webauthn: user not found")
	ErrSessionNotFound = errors.New("webauthn: session not found or expired")
	// ErrSignCountRegression is returned when a credential update would move the
	// signature counter backwards (or not forward) — a clone signal that must
	// never be persisted (docs/DESIGN.md §3.1).
	ErrSignCountRegression = fmt.Errorf("%w: signature counter regression", ErrClonedAuthenticator)
)

// Store persists users and their passkey credentials. In production this is
// backed by the sqlc queries over the users/credentials tables (db/queries);
// here it is an interface so the ceremony logic stays pure and testable.
//
// All lookups are by the opaque WebAuthn user handle; there is no cross-user or
// cross-region enumeration surface by construction (docs/DESIGN.md §5).
type Store interface {
	// GetUser returns the user and their enrolled credentials, or
	// ErrUserNotFound.
	GetUser(ctx context.Context, userID []byte) (User, error)
	// AddCredential appends a newly-registered passkey to the user (used when a
	// user who is ALREADY active enrolls an additional passkey).
	AddCredential(ctx context.Context, userID []byte, cred gowebauthn.Credential) error
	// AddCredentialAndActivateUser atomically persists the user's FIRST passkey
	// AND flips their status from "pending" to "active" (design decision 3,
	// §11.1). Database-backed implementations MUST perform both writes in a
	// single transaction and roll back on any failure, so enrollment can never
	// leave a user "pending" with a credential, nor "active" with none.
	AddCredentialAndActivateUser(ctx context.Context, userID []byte, cred gowebauthn.Credential) error
	// UpdateCredential persists changes to an existing passkey — notably the
	// advanced signature counter after a successful assertion (WebAuthn clone
	// detection, docs/DESIGN.md §3.1).
	UpdateCredential(ctx context.Context, userID []byte, cred gowebauthn.Credential) error
	// SetRecoveryComplete clears the user's recovery_required flag. It is called
	// ONLY after a fresh passkey has been enrolled during an account-recovery
	// session, so the account stays fenced to enrollment-only until recovery is
	// genuinely completed (REQ-005, docs/DESIGN.md §11.1).
	SetRecoveryComplete(ctx context.Context, userID []byte) error
}

// SessionStore holds the WebAuthn SessionData (challenge + parameters) between
// the Begin and Finish steps of a ceremony. The data is one-time-use: Take
// removes it so a challenge cannot be replayed.
type SessionStore interface {
	Save(ctx context.Context, key string, data gowebauthn.SessionData) error
	// Take returns the stored session and deletes it, or ErrSessionNotFound.
	Take(ctx context.Context, key string) (gowebauthn.SessionData, error)
}
