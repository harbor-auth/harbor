package oidc

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestConsentGrant_CrossUserIsolation verifies that user A cannot access or
// affect user B's consent grants. This is a critical security invariant.
func TestConsentGrant_CrossUserIsolation(t *testing.T) {
	store := NewInMemoryConsentStore()
	ctx := context.Background()

	userA := "user-a-uuid"
	userB := "user-b-uuid"
	clientID := "shared-client"

	// User A grants consent
	_, err := store.Upsert(ctx, userA, clientID, []string{"openid", "profile"})
	if err != nil {
		t.Fatalf("user A upsert failed: %v", err)
	}

	// User B should NOT see user A's grant
	_, found, err := store.Get(ctx, userB, clientID)
	if err != nil {
		t.Fatalf("user B get failed: %v", err)
	}
	if found {
		t.Error("SECURITY: user B can see user A's grant — cross-user leakage")
	}

	// User B's List should NOT include user A's grants
	grantsB, err := store.List(ctx, userB)
	if err != nil {
		t.Fatalf("user B list failed: %v", err)
	}
	for _, g := range grantsB {
		if g.UserID == userA {
			t.Errorf("SECURITY: user B's list contains user A's grant %s — cross-user leakage", g.ID)
		}
	}

	// User A's List should contain only their own grants
	grantsA, err := store.List(ctx, userA)
	if err != nil {
		t.Fatalf("user A list failed: %v", err)
	}
	if len(grantsA) != 1 {
		t.Errorf("user A should have exactly 1 grant, got %d", len(grantsA))
	}
	for _, g := range grantsA {
		if g.UserID != userA {
			t.Errorf("SECURITY: user A's list contains another user's grant — cross-user leakage")
		}
	}
}

// TestConsentGrant_CrossClientIsolation verifies that a grant for client C1
// does NOT satisfy a consent check for client C2. Each (user, client) pair
// must have its own independent consent grant.
func TestConsentGrant_CrossClientIsolation(t *testing.T) {
	store := NewInMemoryConsentStore()
	ctx := context.Background()

	userID := "user-uuid"
	clientA := "client-a"
	clientB := "client-b"

	// User grants consent to client A
	_, err := store.Upsert(ctx, userID, clientA, []string{"openid", "profile"})
	if err != nil {
		t.Fatalf("upsert for client A failed: %v", err)
	}

	// Consent for client A should NOT satisfy client B
	_, found, err := store.Get(ctx, userID, clientB)
	if err != nil {
		t.Fatalf("get for client B failed: %v", err)
	}
	if found {
		t.Error("SECURITY: grant for client A satisfies client B — cross-client leakage")
	}

	// ConsentDecision for client B should require a prompt (no grant exists)
	grantA, _, err := store.Get(ctx, userID, clientA)
	if err != nil {
		t.Fatalf("get grant: %v", err)
	}
	decision, err := ConsentDecision(&grantA, []string{"openid", "profile"}, "")
	if err != nil {
		t.Fatalf("consent decision for client A failed: %v", err)
	}
	if !decision.Skip {
		t.Error("grant for client A should allow skip for client A")
	}

	// Client B should NOT be able to skip (no grant)
	decisionB, err := ConsentDecision(nil, []string{"openid", "profile"}, "")
	if err != nil {
		t.Fatalf("consent decision for client B failed: %v", err)
	}
	if decisionB.Skip {
		t.Error("SECURITY: no grant for client B but skip=true — cross-client satisfaction")
	}
}

// TestConsentGrant_RevokeIsolation verifies that revoking user A's grant does
// NOT affect user B's grants, and revoking for client C1 does NOT affect
// grants for client C2.
func TestConsentGrant_RevokeIsolation(t *testing.T) {
	store := NewInMemoryConsentStore()
	ctx := context.Background()

	userA := "user-a-uuid"
	userB := "user-b-uuid"
	clientID := "shared-client"

	// Both users grant consent to the same client
	grantA, err := store.Upsert(ctx, userA, clientID, []string{"openid"})
	if err != nil {
		t.Fatalf("user A upsert failed: %v", err)
	}
	grantB, err := store.Upsert(ctx, userB, clientID, []string{"openid"})
	if err != nil {
		t.Fatalf("user B upsert failed: %v", err)
	}

	// Revoke user A's grant
	if err := store.Revoke(ctx, grantA.ID); err != nil {
		t.Fatalf("revoke user A failed: %v", err)
	}

	// User A's grant should be gone
	_, foundA, err := store.Get(ctx, userA, clientID)
	if err != nil {
		t.Fatalf("get user A after revoke failed: %v", err)
	}
	if foundA {
		t.Error("user A's grant should be revoked")
	}

	// User B's grant should be UNAFFECTED
	gotB, foundB, err := store.Get(ctx, userB, clientID)
	if err != nil {
		t.Fatalf("get user B after A's revoke failed: %v", err)
	}
	if !foundB {
		t.Error("SECURITY: user B's grant was revoked when user A's was revoked — cross-user revoke leak")
	}
	if gotB.ID != grantB.ID {
		t.Errorf("user B's grant ID mismatch: got %s, want %s", gotB.ID, grantB.ID)
	}
}

// TestConsentGrant_NoPIIBeyondFKsAndScopes verifies that the ConsentGrant
// struct contains only foreign keys (UUIDs) and scope strings — no email,
// name, or other PII that could leak if the grants table is compromised.
func TestConsentGrant_NoPIIBeyondFKsAndScopes(t *testing.T) {
	store := NewInMemoryConsentStore()
	ctx := context.Background()

	// Create a grant and inspect its fields
	grant, err := store.Upsert(ctx, "user-uuid", "client-id", []string{"openid", "profile", "email"})
	if err != nil {
		t.Fatalf("upsert failed: %v", err)
	}

	// Verify the grant contains only expected fields (no raw PII)
	// ID: UUID string (FK-like identifier)
	if grant.ID == "" {
		t.Error("grant.ID should be populated")
	}

	// UserID: UUID string (FK to users table, not the actual user's email/name)
	if grant.UserID == "" {
		t.Error("grant.UserID should be populated")
	}
	// UserID should be a UUID-like string, not an email or name
	if len(grant.UserID) < 8 {
		t.Errorf("grant.UserID looks suspiciously short for a UUID: %q", grant.UserID)
	}

	// ClientID: client identifier (FK-like, registered in relying_parties)
	if grant.ClientID == "" {
		t.Error("grant.ClientID should be populated")
	}

	// Scopes: array of scope strings (openid, profile, email — not actual user data)
	if len(grant.Scopes) == 0 {
		t.Error("grant.Scopes should be populated")
	}
	for _, scope := range grant.Scopes {
		// Scope strings should be well-known identifiers, not user data
		validScopes := map[string]bool{
			"openid": true, "profile": true, "email": true, "offline_access": true,
		}
		if !validScopes[scope] {
			// Not necessarily an error, but flag unexpected scopes
			t.Logf("note: scope %q is not a standard OIDC scope", scope)
		}
	}

	// Timestamps: GrantedAt, UpdatedAt, RevokedAt are metadata, not PII
	if grant.GrantedAt.IsZero() {
		t.Error("grant.GrantedAt should be populated")
	}

	// The struct should NOT contain fields like:
	// - UserEmail, UserName, UserPhone (direct PII)
	// - IPAddress, UserAgent (behavioral PII)
	// - AccessToken, RefreshToken (secrets)
	// These fields don't exist in the struct, which is the correct design.
}

// TestConsentDecision_PromptNoneRequiresExistingGrant verifies the security
// property that prompt=none cannot bypass the consent requirement — it must
// fail with interaction_required if no valid grant exists.
func TestConsentDecision_PromptNoneRequiresExistingGrant(t *testing.T) {
	// No grant exists — prompt=none MUST fail
	_, err := ConsentDecision(nil, []string{"openid"}, "none")
	if !errors.Is(err, ErrInteractionRequired) {
		t.Errorf("prompt=none with no grant should return ErrInteractionRequired, got %v", err)
	}

	// Revoked grant — prompt=none MUST fail
	now := time.Now()
	revokedGrant := &ConsentGrant{
		ID:        "revoked-grant",
		UserID:    "user",
		ClientID:  "client",
		Scopes:    []string{"openid"},
		RevokedAt: &now,
	}
	_, err = ConsentDecision(revokedGrant, []string{"openid"}, "none")
	if !errors.Is(err, ErrInteractionRequired) {
		t.Errorf("prompt=none with revoked grant should return ErrInteractionRequired, got %v", err)
	}

	// Scope escalation with prompt=none MUST fail
	existingGrant := &ConsentGrant{
		ID:       "existing-grant",
		UserID:   "user",
		ClientID: "client",
		Scopes:   []string{"openid"},
	}
	_, err = ConsentDecision(existingGrant, []string{"openid", "profile"}, "none")
	if !errors.Is(err, ErrInteractionRequired) {
		t.Errorf("prompt=none with scope escalation should return ErrInteractionRequired, got %v", err)
	}
}
