package mgmtapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
)

// ErrEnrollmentSessionNotFound is returned when an enrollment session key is
// unknown or has expired.
var ErrEnrollmentSessionNotFound = errors.New("mgmtapi: enrollment session not found or expired")

// EnrollmentSessionCookieName is the cookie carrying the enrollment session key
// from POST /enroll to the passkey registration ceremony. It MUST match
// webauthn.enrollmentCookieName — the packages are decoupled, so the value is
// duplicated and kept in sync deliberately.
const EnrollmentSessionCookieName = "harbor_enrollment_session"

// enrollmentSessionTTL bounds how long a just-enrolled user has to complete
// passkey registration before the handoff session expires. It is short:
// enrollment and first-passkey registration are a single, contiguous flow.
const enrollmentSessionTTL = 10 * time.Minute

// EnrollmentSessionStore maps a short-lived, opaque session key to the WebAuthn
// user handle of a just-enrolled user. It bridges POST /enroll (which creates
// the user) and the passkey registration ceremony (which must bind to that same
// user WITHOUT a client-supplied, IDOR-prone user_id — docs/DESIGN.md §9, §11.1).
type EnrollmentSessionStore interface {
	// Save associates key with the given user handle for the store's TTL.
	Save(ctx context.Context, key string, userHandle []byte) error
	// UserHandle returns the user handle for key, or ErrEnrollmentSessionNotFound.
	// Unlike a WebAuthn ceremony session it is NOT one-time-use: both
	// register/begin and register/finish read it within the same enrollment.
	UserHandle(ctx context.Context, key string) ([]byte, error)
}

// NewEnrollmentSessionKey returns a 256-bit random, URL-safe opaque key.
func NewEnrollmentSessionKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
