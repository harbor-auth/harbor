package oidc

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ConsentGrant is the domain representation of a per-(user, RP, scope) consent
// record (docs/DESIGN.md §11). It tracks explicit user consent for each RP and
// scope set, enforced at /authorize to ensure users have granted consent before
// tokens are issued.
type ConsentGrant struct {
	ID        string    // UUID string
	UserID    string    // UUID string
	ClientID  string    // relying_parties.client_id
	Scopes    []string  // canonical sorted scope set
	GrantedAt time.Time // when consent was first granted
	UpdatedAt time.Time // when consent was last updated (e.g. scope change)
	RevokedAt *time.Time // nil = active consent
}

// ConsentStore persists and queries consent grants (per-user, per-RP consent).
// The sqlc-backed implementation is in internal/clients; an in-memory stub is
// available for unit tests that do not require a live DB.
type ConsentStore interface {
	// Get retrieves the active (non-revoked) consent grant for a (userID, clientID)
	// pair. found=false means the user has not (yet) consented to this RP.
	Get(ctx context.Context, userID, clientID string) (ConsentGrant, bool, error)

	// Upsert creates a new consent grant or updates the scopes of an existing
	// active grant. The partial unique index ensures only one active grant per
	// (user, client) pair.
	Upsert(ctx context.Context, userID, clientID string, scopes []string) (ConsentGrant, error)

	// List returns all active (non-revoked) consent grants for a user, newest
	// first — powers the "connected apps" dashboard in harbor-mgmt.
	List(ctx context.Context, userID string) ([]ConsentGrant, error)

	// Revoke soft-deletes a consent grant by its UUID string ID. Only affects
	// active grants; revoking an already-revoked grant is a no-op.
	Revoke(ctx context.Context, id string) error
}

// ConsentDecisionResult holds the outcome of a consent decision check.
type ConsentDecisionResult struct {
	// Skip is true if the existing grant covers all requested scopes and no
	// prompt is required — the flow can proceed directly to code issuance.
	Skip bool
	// Escalation is true if the user has a prior grant but the current request
	// asks for additional scopes not yet consented. The UI should show the
	// incremental scopes being requested.
	Escalation bool
	// MergedScopes contains the union of existing granted scopes and newly
	// requested scopes. Only populated when Escalation is true.
	MergedScopes []string
}

// ErrInteractionRequired is returned by ConsentDecision when prompt=none is
// requested but consent is required (no covering grant exists).
var ErrInteractionRequired = &AuthorizeError{
	Code:        "interaction_required",
	Description: "consent is required but prompt=none was requested",
	Channel:     ChannelRedirect,
}

// ConsentDecision determines whether the /authorize flow should skip the
// consent prompt or show it, based on the existing grant (if any), the
// requested scopes, and the OIDC prompt parameter.
//
// Decision matrix:
//   - grant covers all requested scopes → skip (unless prompt=consent)
//   - no grant or revoked grant → prompt
//   - grant exists but requested scopes exceed it → prompt + escalation
//   - prompt=consent → always prompt (force re-consent)
//   - prompt=none + need consent → error (interaction_required)
//
// The grant parameter may be nil if no active consent exists for the
// (user, client) pair.
func ConsentDecision(grant *ConsentGrant, requestedScopes []string, prompt string) (ConsentDecisionResult, error) {
	canonicalRequested := CanonicalizeScopes(requestedScopes)

	// prompt=consent forces re-prompting regardless of existing grant
	if prompt == "consent" {
		if grant != nil && grant.RevokedAt == nil {
			// Existing grant — check for escalation
			missing := scopesMissing(grant.Scopes, canonicalRequested)
			if len(missing) > 0 {
				return ConsentDecisionResult{
					Skip:         false,
					Escalation:   true,
					MergedScopes: mergeScopes(grant.Scopes, canonicalRequested),
				}, nil
			}
		}
		// Force re-prompt, no escalation
		return ConsentDecisionResult{Skip: false, Escalation: false}, nil
	}

	// No grant or revoked grant → need consent
	if grant == nil || grant.RevokedAt != nil {
		if prompt == "none" {
			return ConsentDecisionResult{}, ErrInteractionRequired
		}
		return ConsentDecisionResult{Skip: false, Escalation: false}, nil
	}

	// Active grant exists — check if it covers requested scopes
	missing := scopesMissing(grant.Scopes, canonicalRequested)
	if len(missing) == 0 {
		// Grant covers all requested scopes → skip consent
		return ConsentDecisionResult{Skip: true, Escalation: false}, nil
	}

	// Scope escalation: grant exists but doesn't cover all requested scopes
	if prompt == "none" {
		return ConsentDecisionResult{}, ErrInteractionRequired
	}
	return ConsentDecisionResult{
		Skip:         false,
		Escalation:   true,
		MergedScopes: mergeScopes(grant.Scopes, canonicalRequested),
	}, nil
}

// scopesMissing returns the scopes in requested that are not in granted.
// Both inputs must be canonicalized (sorted, deduplicated).
func scopesMissing(granted, requested []string) []string {
	grantedSet := make(map[string]struct{}, len(granted))
	for _, s := range granted {
		grantedSet[s] = struct{}{}
	}
	var missing []string
	for _, s := range requested {
		if _, ok := grantedSet[s]; !ok {
			missing = append(missing, s)
		}
	}
	return missing
}

// mergeScopes returns the union of two scope sets, canonicalized.
func mergeScopes(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	for _, s := range a {
		seen[s] = struct{}{}
	}
	for _, s := range b {
		seen[s] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for s := range seen {
		result = append(result, s)
	}
	sort.Strings(result)
	return result
}

// noopConsentStore is a ConsentStore that always returns no grant. Used as the
// default in ServiceConfig when no consent store is wired — the consent check
// effectively becomes a no-op (always requires consent prompt).
type noopConsentStore struct{}

// Compile-time proof that noopConsentStore implements ConsentStore.
var _ ConsentStore = noopConsentStore{}

func (noopConsentStore) Get(_ context.Context, _, _ string) (ConsentGrant, bool, error) {
	return ConsentGrant{}, false, nil
}
func (noopConsentStore) Upsert(_ context.Context, _, _ string, _ []string) (ConsentGrant, error) {
	return ConsentGrant{}, nil
}
func (noopConsentStore) List(_ context.Context, _ string) ([]ConsentGrant, error) {
	return nil, nil
}
func (noopConsentStore) Revoke(_ context.Context, _ string) error {
	return nil
}

// CanonicalizeScopes returns a sorted, deduplicated copy of the input scopes.
// This ensures consistent storage and comparison of scope sets regardless of
// the order in which scopes were requested or granted.
func CanonicalizeScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{}
	}
	// Deduplicate using a map
	seen := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		seen[s] = struct{}{}
	}
	// Build sorted result
	result := make([]string, 0, len(seen))
	for s := range seen {
		result = append(result, s)
	}
	sort.Strings(result)
	return result
}

// InMemoryConsentStore is a dev/test ConsentStore. NOT for production — a real
// store persists consent grants durably so they survive restarts.
type InMemoryConsentStore struct {
	mu      sync.Mutex
	byID    map[string]*ConsentGrant
	byPair  map[string]*ConsentGrant // key: userID+":"+clientID
	counter int                      // monotonically increasing for unique IDs
}

// Compile-time proof that InMemoryConsentStore implements ConsentStore.
var _ ConsentStore = (*InMemoryConsentStore)(nil)

// NewInMemoryConsentStore returns an empty in-memory consent store.
func NewInMemoryConsentStore() *InMemoryConsentStore {
	return &InMemoryConsentStore{
		byID:   make(map[string]*ConsentGrant),
		byPair: make(map[string]*ConsentGrant),
	}
}

// Get implements ConsentStore. Returns only active (non-revoked) grants.
func (s *InMemoryConsentStore) Get(_ context.Context, userID, clientID string) (ConsentGrant, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byPair[userID+":"+clientID]
	if !ok || g.RevokedAt != nil {
		return ConsentGrant{}, false, nil
	}
	// Clone Scopes so caller mutation cannot corrupt the stored grant
	out := *g
	out.Scopes = append([]string(nil), g.Scopes...)
	return out, true, nil
}

// Upsert implements ConsentStore. Creates or updates a consent grant.
func (s *InMemoryConsentStore) Upsert(_ context.Context, userID, clientID string, scopes []string) (ConsentGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	canonicalScopes := CanonicalizeScopes(scopes)
	key := userID + ":" + clientID
	now := time.Now()

	// Check for existing active grant
	if existing, ok := s.byPair[key]; ok && existing.RevokedAt == nil {
		// Update existing grant
		existing.Scopes = append([]string(nil), canonicalScopes...)
		existing.UpdatedAt = now
		// Return a clone
		out := *existing
		out.Scopes = append([]string(nil), existing.Scopes...)
		return out, nil
	}

	// Create new grant
	s.counter++
	id := fmt.Sprintf("consent-%08d", s.counter)
	g := &ConsentGrant{
		ID:        id,
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    append([]string(nil), canonicalScopes...),
		GrantedAt: now,
		UpdatedAt: now,
	}
	s.byID[id] = g
	s.byPair[key] = g

	// Return a clone
	out := *g
	out.Scopes = append([]string(nil), g.Scopes...)
	return out, nil
}

// List implements ConsentStore. Returns only active (non-revoked) grants.
func (s *InMemoryConsentStore) List(_ context.Context, userID string) ([]ConsentGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []ConsentGrant
	for _, g := range s.byID {
		if g.UserID == userID && g.RevokedAt == nil {
			// Clone for consistency
			gc := *g
			gc.Scopes = append([]string(nil), g.Scopes...)
			out = append(out, gc)
		}
	}
	// Sort newest first (by GrantedAt, then by ID as tiebreaker)
	sort.Slice(out, func(i, j int) bool {
		if out[i].GrantedAt.Equal(out[j].GrantedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].GrantedAt.After(out[j].GrantedAt)
	})
	return out, nil
}

// Revoke implements ConsentStore. Soft-deletes by ID.
func (s *InMemoryConsentStore) Revoke(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byID[id]
	if !ok || g.RevokedAt != nil {
		return nil // idempotent
	}
	now := time.Now()
	g.RevokedAt = &now
	return nil
}
