package oidc

import (
	"context"
	"time"
)

// ConsentEventKind enumerates the types of consent lifecycle events that can
// be emitted for audit trails and analytics (docs/DESIGN.md §11.4).
type ConsentEventKind string

const (
	// ConsentEventGranted is emitted when a user grants consent to an RP for
	// the first time (no prior active grant existed).
	ConsentEventGranted ConsentEventKind = "granted"

	// ConsentEventScopeEscalated is emitted when a user approves additional
	// scopes beyond their existing grant (scope escalation).
	ConsentEventScopeEscalated ConsentEventKind = "scope_escalated"

	// ConsentEventRevoked is emitted when a user explicitly revokes their
	// consent grant for an RP (via harbor-mgmt or admin action).
	ConsentEventRevoked ConsentEventKind = "revoked"
)

// ConsentEvent represents a consent lifecycle event for audit and analytics.
// Events are emitted by the consent store on grant creation, scope escalation,
// and revocation. The emitter seam allows plugging in different backends
// (logging, metrics, event bus) without changing the store implementation.
type ConsentEvent struct {
	// Kind identifies the type of consent event (granted, scope_escalated, revoked).
	Kind ConsentEventKind

	// GrantID is the UUID string of the consent grant the event refers to.
	// For revoked events — where only the grant ID is available — this is the
	// primary identifier; audit consumers can resolve the (user, client) pair
	// from it.
	GrantID string

	// UserID is the user's UUID string (the subject of the consent).
	UserID string

	// ClientID is the relying party's client_id (the recipient of consent).
	ClientID string

	// Scopes is the canonical scope set at the time of the event:
	// - For granted: the initially consented scopes
	// - For scope_escalated: the new merged scope set (existing + newly requested)
	// - For revoked: the scopes that were active before revocation
	Scopes []string

	// Timestamp is when the event occurred (UTC).
	Timestamp time.Time
}

// ConsentEventEmitter is the seam for emitting consent lifecycle events.
// Implementations can log events, publish to a message bus, update metrics,
// or any combination. The interface is intentionally minimal to keep the
// consent store decoupled from specific observability backends.
type ConsentEventEmitter interface {
	// Emit sends a consent event to the configured backend(s). Implementations
	// should be non-blocking and handle errors internally (e.g., log and continue)
	// to avoid blocking the consent store's critical path.
	Emit(ctx context.Context, event ConsentEvent) error
}

// noopConsentEventEmitter is a ConsentEventEmitter that does nothing. Used as
// the default when no emitter is configured, allowing the consent store to
// operate without requiring observability infrastructure.
type noopConsentEventEmitter struct{}

// Compile-time proof that noopConsentEventEmitter implements ConsentEventEmitter.
var _ ConsentEventEmitter = noopConsentEventEmitter{}

// Emit implements ConsentEventEmitter. It does nothing and always succeeds.
func (noopConsentEventEmitter) Emit(_ context.Context, _ ConsentEvent) error {
	return nil
}

// NoopConsentEventEmitter returns a ConsentEventEmitter that discards all
// events. Use this as the default when no emitter is configured.
func NoopConsentEventEmitter() ConsentEventEmitter {
	return noopConsentEventEmitter{}
}
