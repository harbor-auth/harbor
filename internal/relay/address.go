package relay

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/harbor-auth/harbor/internal/region"
)

// Token length constants.
const (
	// tokenBytes is the number of random bytes in a relay token.
	// 20 bytes = 160 bits of entropy, yielding a 27-char base64url string.
	// This provides ample collision resistance (~2^80 birthday bound) while
	// keeping the local-part of the email address reasonably short.
	tokenBytes = 20
)

// State represents the lifecycle state of a relay address.
type State string

const (
	// StateActive means the relay address is forwarding mail to the user's real inbox.
	StateActive State = "active"
	// StateDeactivated means mail to this address will hard-bounce (kill switch).
	// Deactivation is independent of login grant revocation (§7.5.4).
	StateDeactivated State = "deactivated"
	// StateBYODomain means the user has verified ownership of a custom domain
	// and is using it for this relay address.
	StateBYODomain State = "byo_domain"
)

// Errors returned by this package.
var (
	ErrInvalidState  = errors.New("relay: invalid state")
	ErrRandFailure   = errors.New("relay: random number generator failure")
	ErrEmptyUserID   = errors.New("relay: user_id must be non-empty")
	ErrEmptyClientID = errors.New("relay: client_id must be non-empty")
	ErrEmptyEmail    = errors.New("relay: real email must be non-empty")
	ErrInvalidRegion = errors.New("relay: invalid region")
)

// Address represents a per-(user, RP) email relay address.
type Address struct {
	// ID is the database primary key (UUID).
	ID uuid.UUID

	// Token is the opaque, unlinkable relay token. It is randomly generated
	// (not derived from UserID) so two RPs' addresses for the same user are
	// completely uncorrelated. This forms the local-part of the relay email:
	// <token>@relay.<region>.harbor.id
	Token string

	// UserID is the internal user identifier this relay address belongs to.
	UserID uuid.UUID

	// ClientID is the RP (relying party) this relay address is scoped to.
	ClientID string

	// State is the current lifecycle state of this relay address.
	State State

	// Region is the user's home region. The mapping is stored only in this
	// region and never cross-region replicated (§5).
	Region region.Region

	// CreatedAt is when this relay address was minted.
	CreatedAt time.Time

	// DeactivatedAt is when this relay address was deactivated (nil if active).
	DeactivatedAt *time.Time
}

// Mapping holds the envelope-encrypted link between a relay address and the
// user's real email. This is the only data that connects the opaque relay
// token back to a real person, and it lives behind regional envelope crypto.
type Mapping struct {
	// RelayToken is the opaque token (the local-part of the relay email).
	RelayToken string

	// RealEmail is the user's actual email address (plaintext; encrypted at rest).
	RealEmail string

	// UserID is included for audit/lookup purposes.
	UserID uuid.UUID

	// ClientID is the RP this mapping is scoped to.
	ClientID string

	// Region is where this mapping is stored.
	Region region.Region
}

// TokenGenerator generates opaque, unlinkable relay tokens.
type TokenGenerator interface {
	// Generate returns a fresh, cryptographically random relay token.
	// The token is NOT derived from userID or clientID in any way —
	// it is purely random, ensuring unlinkability across RPs.
	Generate() (string, error)
}

// DefaultTokenGenerator generates relay tokens using crypto/rand.
type DefaultTokenGenerator struct {
	rand io.Reader
}

// NewTokenGenerator returns a TokenGenerator backed by crypto/rand.
func NewTokenGenerator() *DefaultTokenGenerator {
	return &DefaultTokenGenerator{rand: rand.Reader}
}

// newTokenGeneratorWithReader returns a TokenGenerator with a custom random
// reader (for testing with deterministic output).
func newTokenGeneratorWithReader(r io.Reader) *DefaultTokenGenerator {
	return &DefaultTokenGenerator{rand: r}
}

// Generate returns a fresh relay token: 20 random bytes encoded as base64url
// (no padding). The token is purely random and not derived from any user or
// client identifier, ensuring that two RPs' relay addresses for the same user
// are completely uncorrelated.
func (g *DefaultTokenGenerator) Generate() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := io.ReadFull(g.rand, b); err != nil {
		return "", ErrRandFailure
	}
	// Defense-in-depth: reject all-zero output (catastrophic RNG failure).
	allZero := true
	for _, v := range b {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "", ErrRandFailure
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewAddress creates a new relay Address with a freshly generated token.
// The token is randomly generated (not derived from userID or clientID),
// ensuring unlinkability across RPs.
func NewAddress(gen TokenGenerator, userID uuid.UUID, clientID string, realEmail string, reg region.Region) (*Address, *Mapping, error) {
	if userID == uuid.Nil {
		return nil, nil, ErrEmptyUserID
	}
	if clientID == "" {
		return nil, nil, ErrEmptyClientID
	}
	if realEmail == "" {
		return nil, nil, ErrEmptyEmail
	}
	if reg == "" {
		return nil, nil, ErrInvalidRegion
	}

	token, err := gen.Generate()
	if err != nil {
		return nil, nil, fmt.Errorf("relay: failed to generate token: %w", err)
	}

	now := time.Now().UTC()
	addr := &Address{
		ID:        uuid.New(),
		Token:     token,
		UserID:    userID,
		ClientID:  clientID,
		State:     StateActive,
		Region:    reg,
		CreatedAt: now,
	}

	mapping := &Mapping{
		RelayToken: token,
		RealEmail:  realEmail,
		UserID:     userID,
		ClientID:   clientID,
		Region:     reg,
	}

	return addr, mapping, nil
}

// FormatEmail returns the full relay email address for a given token and region.
// Format: <token>@relay.<region>.harbor.id
func FormatEmail(token string, reg region.Region) string {
	return fmt.Sprintf("%s@relay.%s.harbor.id", token, reg)
}

// ParseState validates and returns a State from a string.
func ParseState(s string) (State, error) {
	switch State(s) {
	case StateActive, StateDeactivated, StateBYODomain:
		return State(s), nil
	default:
		return "", ErrInvalidState
	}
}

// IsActive returns true if the address is in the Active state (forwarding mail).
func (a *Address) IsActive() bool {
	return a.State == StateActive
}

// IsDeactivated returns true if the address has been deactivated (kill switch).
func (a *Address) IsDeactivated() bool {
	return a.State == StateDeactivated
}

// IsBYODomain returns true if the address is using a user-verified custom domain.
func (a *Address) IsBYODomain() bool {
	return a.State == StateBYODomain
}

// CanReceiveMail returns true if mail to this address should be accepted.
// Active and BYO-domain addresses accept mail; Deactivated addresses hard-bounce.
// This is the kill switch check for the inbound MTA (§7.5.4).
func (a *Address) CanReceiveMail() bool {
	return a.State == StateActive || a.State == StateBYODomain
}

// Deactivate transitions the address to the Deactivated state (hard-bounce kill switch).
// This sets the state and records the deactivation timestamp.
// Deactivation is independent of login grant revocation (§7.5.4): killing email
// does not revoke login, and revoking login does not deactivate the relay.
func (a *Address) Deactivate() {
	a.State = StateDeactivated
	now := time.Now().UTC()
	a.DeactivatedAt = &now
}

// Reactivate transitions the address from Deactivated back to Active state.
// This clears the deactivation timestamp and restores mail forwarding.
func (a *Address) Reactivate() {
	a.State = StateActive
	a.DeactivatedAt = nil
}

// SetBYODomain transitions the address to the BYO-domain state.
// This is called after the user has verified ownership of their custom domain.
func (a *Address) SetBYODomain() {
	a.State = StateBYODomain
}
