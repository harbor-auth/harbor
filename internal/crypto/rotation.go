package crypto

import "time"

// KeyState represents the lifecycle state of a signing key.
// Keys progress through states: Pending → Active → Retired.
type KeyState string

const (
	// KeyStatePending indicates a newly created key that is published in JWKS
	// but not yet used for signing. This grace period allows RPs to refresh
	// their JWKS cache before the key becomes active.
	KeyStatePending KeyState = "pending"

	// KeyStateActive indicates the key currently used for signing new tokens.
	// Exactly one key can be active at any time (enforced by DB constraint).
	KeyStateActive KeyState = "active"

	// KeyStateRetired indicates a key that has been rotated out. Retired keys
	// are removed from JWKS; tokens signed by retired keys will fail verification.
	KeyStateRetired KeyState = "retired"
)

// String returns the string representation of the KeyState.
func (s KeyState) String() string { return string(s) }

// IsValid reports whether s is a recognized KeyState value.
func (s KeyState) IsValid() bool {
	switch s {
	case KeyStatePending, KeyStateActive, KeyStateRetired:
		return true
	default:
		return false
	}
}

// SigningKeyMetadata holds the lifecycle metadata for a signing key.
// This is the domain representation of a signing key's state, separate from
// the database row representation in internal/clients.
type SigningKeyMetadata struct {
	// Kid is the key identifier (RFC 7517), typically a JWK thumbprint or
	// base64url(SHA256(pubkey)[:8]). Immutable after creation.
	Kid string

	// State is the current lifecycle state: pending, active, or retired.
	State KeyState

	// CreatedAt is when the key was generated.
	CreatedAt time.Time

	// PromotedAt is when the key transitioned to active state. Nil for pending keys.
	PromotedAt *time.Time

	// RetiredAt is when the key transitioned to retired state. Nil for
	// pending and active keys.
	RetiredAt *time.Time
}

// IsLive reports whether the key should appear in the JWKS endpoint.
// Live keys are those in pending or active state.
func (m SigningKeyMetadata) IsLive() bool {
	return m.State == KeyStatePending || m.State == KeyStateActive
}

// MultiKeySigner manages multiple signing keys for JWKS kid rotation
// (docs/DESIGN.md §7.3, §3.5.4). It maintains exactly one active signing key
// and zero or more pending keys (newly rotated, awaiting promotion) in the
// JWKS response.
//
// Implementations must be safe for concurrent use.
type MultiKeySigner interface {
	// ActiveSigner returns the Signer for the currently active signing key.
	// All new tokens are signed with this key. Returns nil if no active key
	// exists (should not happen in normal operation).
	ActiveSigner() Signer

	// AllLiveJWKs returns the public JWKs for all live keys (pending + active).
	// This is the set of keys that should be published in the JWKS endpoint.
	// Retired keys are excluded.
	AllLiveJWKs() []JWK

	// RotateTo initiates rotation to newSigner. The new key enters pending state
	// (published in JWKS but not signing). After the grace period, the caller
	// should promote it to active via the rotation manager. Returns an error if
	// the rotation cannot be initiated (e.g., duplicate kid).
	RotateTo(newSigner Signer) error
}
