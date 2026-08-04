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

// SignupReturnToCookieName carries the return_to value bff.GetSignup already
// validated (bff.ValidateReturnTo) through to POST /enroll, which folds it
// into the new enrollment session as real server-side state — the opaque
// carrier design.md Decision 5 / REQ-004 requires, rather than re-parsing a
// client-controlled query string at every hop of the signup journey. Its
// value is only ever the already-validated output of ValidateReturnTo: GET
// /signup is the only handler that sets it, and it does so only after
// validating. A caller who bypasses GET /signup and forges this cookie
// directly can only ever affect their own enrollment session (nothing here
// lets one browser's cookie influence another's), so PostEnroll trusts it
// without a second allowlist check — the same trust level already extended to
// this cookie's sibling, EnrollmentSessionCookieName.
const SignupReturnToCookieName = "harbor_signup_return_to"

// enrollmentSessionTTL bounds how long a just-enrolled user has to complete
// passkey registration before the handoff session expires. It is short:
// enrollment and first-passkey registration are a single, contiguous flow.
const enrollmentSessionTTL = 10 * time.Minute

// EnrollmentSessionStore maps a short-lived, opaque session key to the WebAuthn
// user handle of a just-enrolled (or recovering) user. It bridges POST /enroll
// or POST /recovery/complete (which resolve/create the user) and the passkey
// registration ceremony (which must bind to that same user WITHOUT a
// client-supplied, IDOR-prone user_id — docs/DESIGN.md §9, §11.1).
type EnrollmentSessionStore interface {
	// Save associates key with the given user handle for the store's TTL.
	// recovery marks the session as originating from the lost-device recovery
	// ceremony (POST /recovery/complete) rather than first-time enrollment
	// (POST /enroll); see UserHandle for how it is used. returnTo is the
	// already-validated return_to captured at GET /signup (empty when none was
	// set, e.g. a lost-device recovery session) — carried through so the
	// post-registration handoff can copy it onto the BFF session it issues
	// (design.md Decision 5 / REQ-004).
	Save(ctx context.Context, key string, userHandle []byte, recovery bool, returnTo string) error
	// UserHandle returns the user handle, recovery flag, and return_to for
	// key, or ErrEnrollmentSessionNotFound. The webauthn package's
	// register/finish ceremony uses recovery to decide whether to activate a
	// pending user (first passkey) or clear recovery_required on an
	// already-active one (fresh passkey after a lost-device recovery). Unlike
	// a WebAuthn ceremony session it is NOT one-time-use: both register/begin
	// and register/finish read it within the same enrollment.
	UserHandle(ctx context.Context, key string) (userHandle []byte, recovery bool, returnTo string, err error)
}

// NewEnrollmentSessionKey returns a 256-bit random, URL-safe opaque key.
func NewEnrollmentSessionKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
