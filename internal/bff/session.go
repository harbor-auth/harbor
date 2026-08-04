package bff

import (
	"context"
	"errors"
	"time"

	"github.com/harbor-auth/harbor/internal/oidc"
)

// Sentinel errors from the BFF session store. Handlers map these to HTTP status
// codes with PII-free messages (docs/DESIGN.md §6.5).
var (
	// ErrBFFSessionNotFound is returned when no session exists for the given
	// request ID (never issued, already consumed, or pruned).
	ErrBFFSessionNotFound = errors.New("bff: session not found")
	// ErrBFFSessionExpired is returned when the session exists but has exceeded
	// its TTL. Callers should treat this the same as NotFound for security, but
	// may log differently for diagnostics.
	ErrBFFSessionExpired = errors.New("bff: session expired")
)

// SessionScope defines the scope of operations allowed for a BFF session.
// This is used to restrict users in recovery mode to enrollment-only operations.
type SessionScope string

const (
	// SessionScopeFull allows all operations (normal authenticated session).
	SessionScopeFull SessionScope = "full"
	// SessionScopeEnrollmentOnly restricts the session to passkey enrollment only.
	// Users with recovery_required=true get this scope until they complete recovery.
	SessionScopeEnrollmentOnly SessionScope = "enrollment_only"
)

// BFFSessionRecord holds the state of a BFF session across the OIDC/passkey
// ceremony flow. It is created at /authorize and consumed after FinishAssertion.
//
// Fields are exported for JSON serialization (Redis store) but are otherwise
// treated as opaque by callers.
type BFFSessionRecord struct {
	// RequestID is the opaque, CSPRNG-generated identifier for this session
	// (256-bit, base64url-encoded). It is the store key and the value carried
	// in the __Host-harbor-bff cookie.
	RequestID string

	// State is the OIDC state parameter from the /authorize request, echoed
	// back to the RP after the ceremony completes.
	State string

	// ClientID is the RP's client_id from the /authorize request.
	ClientID string

	// RedirectURI is the validated redirect_uri from the /authorize request.
	RedirectURI string

	// Scope is the validated scope from the /authorize request.
	Scope string

	// Nonce is the OIDC nonce from the /authorize request for ID token replay protection.
	Nonce string

	// CodeChallenge is the PKCE code_challenge from the /authorize request.
	CodeChallenge string

	// CodeChallengeMethod is the PKCE code_challenge_method (always S256).
	CodeChallengeMethod string

	// Prompt preserves the OIDC prompt parameter across browser authentication.
	Prompt string

	// ConsentPending proves that authentication completed and this request is
	// waiting for an explicit, one-time consent decision.
	ConsentPending bool

	// UserID is the authenticated user's internal UUID, populated by
	// FinishAssertion after a successful passkey ceremony. Empty until the
	// user authenticates.
	UserID string

	// SessionScope defines what operations are allowed for this session.
	// Users with recovery_required=true get SessionScopeEnrollmentOnly.
	// Defaults to SessionScopeFull for normal sessions.
	SessionScope SessionScope

	// RecoveryRequired indicates whether the user must complete account recovery
	// setup before normal use. When true, the session scope is enrollment-only.
	RecoveryRequired bool

	// AuthMethod is the authentication method used during the login ceremony.
	// It is set by FinishLoginWithParsedData (passkey) or the TOTP/recovery-code
	// step-up handler. The zero value (empty string) means the method is unknown;
	// MapAuthMethodToACRAMR will fail-closed and omit ACR/AMR claims.
	AuthMethod oidc.AuthMethod

	// MFAVerifiedAt is the absolute time of the session's most recent successful
	// step-up (MFA) verification. The zero value means the session has never
	// passed a step-up challenge. The step-up gate treats a verification as
	// valid only while now-MFAVerifiedAt is within the gate's TTL, so a stale
	// verification re-challenges the user before a sensitive action
	// (docs/DESIGN.md §3.1, §7.3).
	MFAVerifiedAt time.Time

	// BrowserNonceHash is the SHA-256 hash of the one-time browser nonce
	// minted at /authorize. It is used to bind the session to the specific
	// browser that initiated the flow and prevent session fixation attacks
	// (docs/plans/fix-bff-session-binding.md). The hash is stored rather than
	// the raw nonce so that a store compromise does not yield live cookies.
	BrowserNonceHash []byte

	// ExpiresAt is the absolute time after which the session is invalid.
	// Callers must enforce this; the store may also TTL-evict.
	ExpiresAt time.Time

	// ReturnTo is the return_to value validated once, at GET /signup
	// (returnto.go's ValidateReturnTo), and carried from there as opaque
	// server-side session state through the rest of the public signup journey
	// (design.md Decision 5 / REQ-004): /signup -> /signup/passkey -> the
	// WebAuthn ceremony -> the post-registration handoff -> /signup/recovery
	// -> /signup/success. Empty when the journey never captured one (e.g. a
	// lost-device recovery session, or a signup that skipped return_to
	// entirely) — readers must fall back to the fixed same-origin default.
	ReturnTo string
}

// BFFSessionStore persists BFF session records across the OIDC/passkey ceremony
// flow. The session is created at /authorize, updated with the authenticated
// user_id after FinishAssertion, and deleted after the auth code is issued.
//
// Implementations must be safe for concurrent use. Production uses Redis with
// a 5-minute TTL (docs/plans/bff-session-middleware.md); tests provide isolated
// fixtures from test-only support.
type BFFSessionStore interface {
	// Create stores a new session record. Returns an error if a session with
	// the same RequestID already exists (collision on CSPRNG output is a
	// critical failure).
	Create(ctx context.Context, record BFFSessionRecord) error

	// Get retrieves the session record by RequestID. Returns
	// ErrBFFSessionNotFound if no such session exists, or ErrBFFSessionExpired
	// if the session has exceeded its TTL.
	Get(ctx context.Context, requestID string) (BFFSessionRecord, error)

	// SetUser updates the UserID field of an existing session. This is called
	// after FinishAssertion to record the authenticated identity. Returns
	// ErrBFFSessionNotFound if the session does not exist.
	SetUser(ctx context.Context, requestID string, userID string) error

	// SetUserWithRecoveryStatus updates the UserID and RecoveryRequired fields.
	// If recoveryRequired is true, the session scope is set to enrollment-only.
	// This is called after FinishAssertion when the user's recovery status is known.
	SetUserWithRecoveryStatus(ctx context.Context, requestID, userID string, recoveryRequired bool) error

	// SetMFAVerified stamps the session with the time of a successful step-up
	// (MFA) verification. The step-up gate (stepup.go) reads MFAVerifiedAt to
	// decide whether a fresh challenge is required. Returns ErrBFFSessionNotFound
	// if the session does not exist.
	SetMFAVerified(ctx context.Context, requestID string, verifiedAt time.Time) error

	// SetAuthMethod records the authentication method used during the login
	// ceremony. This is used to emit the correct ACR/AMR claims in the issued
	// tokens. Returns ErrBFFSessionNotFound if the session does not exist.
	SetAuthMethod(ctx context.Context, requestID string, method oidc.AuthMethod) error

	// SetConsentPending marks an authenticated authorization session as awaiting
	// an explicit consent decision.
	SetConsentPending(ctx context.Context, requestID string) error

	// Consume atomically removes and returns a session. It is the one-time gate
	// for consent decisions and authorization-code issuance.
	Consume(ctx context.Context, requestID string) (BFFSessionRecord, error)

	// Delete removes the session record. This is called after the auth code is
	// issued (one-time use). A no-op if the session does not exist.
	Delete(ctx context.Context, requestID string) error
}
