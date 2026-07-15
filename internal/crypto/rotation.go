package crypto

import (
	"context"
	"errors"
	"fmt"
	"time"
)

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

// RotationConfig holds the timing parameters for key rotation.
// GracePeriod is the delay before a pending key becomes active (allowing RPs
// to refresh their JWKS cache). OverlapWindow is how long the old key remains
// in JWKS after the new key is promoted (allowing in-flight tokens to verify).
type RotationConfig struct {
	// GracePeriod is the time a new key stays in pending state before being
	// promoted to active. During this window the key is published in JWKS but
	// not used for signing, giving RPs time to refresh their JWKS cache.
	// Default: 60 seconds.
	GracePeriod time.Duration

	// OverlapWindow is how long the old active key stays in JWKS after the
	// new key is promoted. This allows in-flight tokens signed with the old
	// key to still verify. Default: 15 minutes (typical JWT max-age).
	OverlapWindow time.Duration
}

// DefaultRotationConfig returns a RotationConfig with sensible defaults:
// 60-second grace period and 15-minute overlap window.
func DefaultRotationConfig() RotationConfig {
	return RotationConfig{
		GracePeriod:   60 * time.Second,
		OverlapWindow: 15 * time.Minute,
	}
}

// EmergencyRotationConfig returns a RotationConfig for emergency rotation
// (§3.5.4 "nuclear option"): zero grace period and zero overlap window.
// The old key disappears from JWKS immediately — all in-flight tokens with
// the old kid are rejected instantly. Use only when the signing key is
// confirmed compromised.
func EmergencyRotationConfig() RotationConfig {
	return RotationConfig{
		GracePeriod:   0,
		OverlapWindow: 0,
	}
}

// Rotation errors.
var (
	// ErrNoActiveKey is returned when no active signing key exists.
	ErrNoActiveKey = errors.New("crypto: no active signing key")

	// ErrNoPendingKey is returned when promotion is attempted but no pending key exists.
	ErrNoPendingKey = errors.New("crypto: no pending key to promote")

	// ErrKeyNotReady is returned when a key is not ready for state transition.
	ErrKeyNotReady = errors.New("crypto: key not ready for state transition")

	// ErrDuplicateKid is returned when attempting to add a key with a kid that already exists.
	ErrDuplicateKid = errors.New("crypto: duplicate kid")
)

// RotationManager implements the signing key rotation state machine
// (docs/DESIGN.md §7.3, §3.5.4). It tracks pending → active → retired
// transitions based on configured timing windows.
//
// The state machine flow:
//
//	[new key created] → pending (in JWKS, not signing)
//	                        │
//	                   grace period
//	                        │
//	                        ▼
//	                     active (signing new tokens)
//	                        │
//	                  overlap window
//	                        │
//	                        ▼
//	                     retired (removed from JWKS)
//
// RotationManager is stateless; it computes transition eligibility from
// key metadata and the current time. Actual state changes are performed
// by the SigningKeyStore passed to each method.
type RotationManager struct {
	config RotationConfig
	clock  func() time.Time
}

// NewRotationManager creates a RotationManager with the given config.
func NewRotationManager(config RotationConfig) *RotationManager {
	return &RotationManager{
		config: config,
		clock:  time.Now,
	}
}

// WithClock returns a copy of the RotationManager using the provided clock
// function. Intended for testing with a controllable time source.
func (m *RotationManager) WithClock(clock func() time.Time) *RotationManager {
	return &RotationManager{
		config: m.config,
		clock:  clock,
	}
}

// Config returns the rotation configuration.
func (m *RotationManager) Config() RotationConfig {
	return m.config
}

// PromotionTime returns when a pending key should be promoted to active.
// This is createdAt + GracePeriod.
func (m *RotationManager) PromotionTime(createdAt time.Time) time.Time {
	return createdAt.Add(m.config.GracePeriod)
}

// RetirementTime returns when an active key should be retired.
// This is promotedAt + OverlapWindow.
func (m *RotationManager) RetirementTime(promotedAt time.Time) time.Time {
	return promotedAt.Add(m.config.OverlapWindow)
}

// ShouldPromote reports whether a pending key is ready to become active.
// A key is ready when now >= createdAt + GracePeriod.
func (m *RotationManager) ShouldPromote(key SigningKeyMetadata) bool {
	if key.State != KeyStatePending {
		return false
	}
	return !m.clock().Before(m.PromotionTime(key.CreatedAt))
}

// ShouldRetire reports whether an active key is ready to be retired.
// A key is ready when now >= promotedAt + OverlapWindow.
// Returns false if the key is not active or has no promotion timestamp.
func (m *RotationManager) ShouldRetire(key SigningKeyMetadata) bool {
	if key.State != KeyStateActive {
		return false
	}
	if key.PromotedAt == nil {
		return false
	}
	return !m.clock().Before(m.RetirementTime(*key.PromotedAt))
}

// RotationSchedule holds the computed timestamps for a rotation operation.
type RotationSchedule struct {
	// NewKid is the key identifier of the new signing key.
	NewKid string

	// CreatedAt is when the new key was created (entered pending state).
	CreatedAt time.Time

	// PromoteAt is when the new key will become active.
	PromoteAt time.Time

	// OldKid is the key identifier of the current active key (if any).
	OldKid string

	// RetireOldAt is when the old key will be retired (removed from JWKS).
	// Zero if there is no old key.
	RetireOldAt time.Time

	// IsEmergency indicates whether this is an emergency rotation
	// (zero grace period and overlap window).
	IsEmergency bool
}

// ComputeSchedule calculates the rotation schedule for initiating a new key.
// createdAt is when the new key was created; oldPromotedAt is when the current
// active key was promoted (nil if no active key exists).
func (m *RotationManager) ComputeSchedule(newKid string, createdAt time.Time, oldKid string, oldPromotedAt *time.Time) RotationSchedule {
	schedule := RotationSchedule{
		NewKid:      newKid,
		CreatedAt:   createdAt,
		PromoteAt:   m.PromotionTime(createdAt),
		OldKid:      oldKid,
		IsEmergency: m.config.GracePeriod == 0 && m.config.OverlapWindow == 0,
	}

	// For the old key retirement: if the new key promotes at time T, the old
	// key retires at T + OverlapWindow. But we compute from when the new key
	// will be promoted (which becomes the old key's effective "end of active").
	if oldKid != "" {
		schedule.RetireOldAt = schedule.PromoteAt.Add(m.config.OverlapWindow)
	}

	return schedule
}

// SigningKeyStateUpdater is the interface for updating signing key state.
// This is a subset of SigningKeyStore to avoid circular dependencies.
type SigningKeyStateUpdater interface {
	// SetState updates a key's state and timestamps.
	SetState(ctx context.Context, id string, state string, promotedAt, retiredAt *time.Time) (SigningKeyRecord, error)

	// Retire marks a key as retired by kid.
	Retire(ctx context.Context, kid string) (SigningKeyRecord, error)
}

// SigningKeyRecord is the interface for a signing key record.
// This allows the RotationManager to work with different key storage implementations.
type SigningKeyRecord interface {
	GetID() string
	GetKid() string
	GetState() string
	GetCreatedAt() time.Time
	GetPromotedAt() *time.Time
	GetRetiredAt() *time.Time
}

// Promote transitions a pending key to active state. It sets the promoted_at
// timestamp to the current time. Returns ErrKeyNotReady if the grace period
// has not elapsed.
func (m *RotationManager) Promote(ctx context.Context, key SigningKeyMetadata, store SigningKeyStateUpdater, keyID string) error {
	if key.State != KeyStatePending {
		return fmt.Errorf("%w: key %q is %s, not pending", ErrKeyNotReady, key.Kid, key.State)
	}
	if !m.ShouldPromote(key) {
		return fmt.Errorf("%w: grace period not elapsed for key %q", ErrKeyNotReady, key.Kid)
	}

	now := m.clock()
	_, err := store.SetState(ctx, keyID, string(KeyStateActive), &now, nil)
	if err != nil {
		return fmt.Errorf("crypto: promote key %q: %w", key.Kid, err)
	}
	return nil
}

// Retire transitions an active key to retired state. If force is true, the
// overlap window check is skipped (emergency rotation). Returns ErrKeyNotReady
// if the overlap window has not elapsed and force is false.
func (m *RotationManager) Retire(ctx context.Context, key SigningKeyMetadata, store SigningKeyStateUpdater, force bool) error {
	if key.State != KeyStateActive {
		return fmt.Errorf("%w: key %q is %s, not active", ErrKeyNotReady, key.Kid, key.State)
	}
	if !force && !m.ShouldRetire(key) {
		return fmt.Errorf("%w: overlap window not elapsed for key %q", ErrKeyNotReady, key.Kid)
	}

	_, err := store.Retire(ctx, key.Kid)
	if err != nil {
		return fmt.Errorf("crypto: retire key %q: %w", key.Kid, err)
	}
	return nil
}

// ToMetadata converts a SigningKeyRecord to SigningKeyMetadata.
// This is a helper for bridging between the clients and crypto packages.
func ToMetadata(r SigningKeyRecord) SigningKeyMetadata {
	return SigningKeyMetadata{
		Kid:        r.GetKid(),
		State:      KeyState(r.GetState()),
		CreatedAt:  r.GetCreatedAt(),
		PromotedAt: r.GetPromotedAt(),
		RetiredAt:  r.GetRetiredAt(),
	}
}
