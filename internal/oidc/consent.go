package oidc

import (
	"sort"
	"time"
)

// ConsentGrant is the domain representation of a per-(user, RP, scope) consent
// record (docs/DESIGN.md §11). It tracks explicit user consent for each RP and
// scope set, enforced at /authorize to ensure users have granted consent before
// tokens are issued.
type ConsentGrant struct {
	ID        string     // UUID string
	UserID    string     // UUID string
	ClientID  string     // relying_parties.client_id
	Scopes    []string   // canonical sorted scope set
	GrantedAt time.Time  // when consent was first granted
	UpdatedAt time.Time  // when consent was last updated (e.g. scope change)
	RevokedAt *time.Time // nil = active consent
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
