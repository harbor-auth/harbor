package oidcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/harbor/harbor/internal/clients"
	"github.com/harbor/harbor/internal/gen/openapi"
	"github.com/harbor/harbor/internal/oidc"
)

// fakeRevokedJTIStore is a test double for RevokedJTIStore.
type fakeRevokedJTIStore struct {
	inserted []clients.RevokedJTI
	err      error
}

func (f *fakeRevokedJTIStore) Insert(_ context.Context, jti, reason string, expiresAt time.Time) (clients.RevokedJTI, error) {
	if f.err != nil {
		return clients.RevokedJTI{}, f.err
	}
	row := clients.RevokedJTI{
		JTI:       jti,
		Reason:    reason,
		ExpiresAt: expiresAt,
		RevokedAt: time.Now(),
	}
	f.inserted = append(f.inserted, row)
	return row, nil
}

// fakeRevocationPublisher is a test double for RevocationPublisher.
type fakeRevocationPublisher struct {
	published []string
	err       error
}

func (f *fakeRevocationPublisher) Publish(_ context.Context, _, message string) error {
	if f.err != nil {
		return f.err
	}
	f.published = append(f.published, message)
	return nil
}

func TestPostAdminRevokeJwt_NotConfigured(t *testing.T) {
	// Server with no revocation store returns 503
	srv := &Server{}

	req := httptest.NewRequest(http.MethodPost, "/admin/revoke-jwt", nil)
	w := httptest.NewRecorder()

	srv.PostAdminRevokeJwt(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestPostAdminRevokeJwt_MissingJTI(t *testing.T) {
	store := &fakeRevokedJTIStore{}
	srv := &Server{revoked: store}

	body := `{"reason": "emergency_kill", "expires_at": "2030-01-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/revoke-jwt", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	srv.PostAdminRevokeJwt(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestPostAdminRevokeJwt_InvalidReason(t *testing.T) {
	store := &fakeRevokedJTIStore{}
	srv := &Server{revoked: store}

	body := `{"jti": "test-jti", "reason": "invalid_reason", "expires_at": "2030-01-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/revoke-jwt", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	srv.PostAdminRevokeJwt(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestPostAdminRevokeJwt_MissingExpiresAt(t *testing.T) {
	store := &fakeRevokedJTIStore{}
	srv := &Server{revoked: store}

	body := `{"jti": "test-jti", "reason": "emergency_kill"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/revoke-jwt", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	srv.PostAdminRevokeJwt(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestPostAdminRevokeJwt_Success(t *testing.T) {
	store := &fakeRevokedJTIStore{}
	filter := oidc.NewInMemoryRevocationFilter()
	publisher := &fakeRevocationPublisher{}

	srv := &Server{
		revoked:    store,
		filter:     filter,
		publisher:  publisher,
		revChannel: "test-channel",
	}

	expiresAt := time.Now().Add(15 * time.Minute)
	body, err := json.Marshal(openapi.RevokeJwtRequest{
		Jti:       "revoked-jti-123",
		Reason:    openapi.EmergencyKill,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/revoke-jwt", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	srv.PostAdminRevokeJwt(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify JTI was inserted into store
	if len(store.inserted) != 1 {
		t.Fatalf("expected 1 insert, got %d", len(store.inserted))
	}
	if store.inserted[0].JTI != "revoked-jti-123" {
		t.Errorf("expected JTI 'revoked-jti-123', got %q", store.inserted[0].JTI)
	}

	// Verify JTI was added to local filter
	if !filter.MightContain("revoked-jti-123") {
		t.Error("expected filter to contain revoked JTI")
	}

	// Verify JTI was published
	if len(publisher.published) != 1 {
		t.Fatalf("expected 1 publish, got %d", len(publisher.published))
	}
	if publisher.published[0] != "revoked-jti-123" {
		t.Errorf("expected published JTI 'revoked-jti-123', got %q", publisher.published[0])
	}

	// Verify response body
	var resp openapi.RevokeJwtResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.Jti != "revoked-jti-123" {
		t.Errorf("expected response JTI 'revoked-jti-123', got %q", resp.Jti)
	}
}

func TestPostAdminRevokeJwt_FilterAddedEvenWithoutPublisher(t *testing.T) {
	// Test that filter is updated even when publisher is nil
	store := &fakeRevokedJTIStore{}
	filter := oidc.NewInMemoryRevocationFilter()

	srv := &Server{
		revoked: store,
		filter:  filter,
		// publisher is nil — single-replica dev mode
	}

	body, err := json.Marshal(openapi.RevokeJwtRequest{
		Jti:       "local-only-jti",
		Reason:    openapi.UserRequest,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/revoke-jwt", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	srv.PostAdminRevokeJwt(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Filter should still be updated
	if !filter.MightContain("local-only-jti") {
		t.Error("expected filter to contain JTI even without publisher")
	}
}

// Integration test: issue → revoke → verify blocked
func TestEmergencyRevocationFlow_IssueRevokeVerify(t *testing.T) {
	// This test verifies the complete emergency revocation flow:
	// 1. A JTI exists in the filter
	// 2. MightContain returns true (token would be blocked)
	// 3. Demonstrates the verification path

	filter := oidc.NewBloomRevocationFilter(oidc.DefaultBloomCapacity, oidc.DefaultBloomFPRate)

	// Simulate a JTI from an issued JWT
	issuedJTI := "jwt-abc123-issued-token"

	// Initially, the JTI is NOT in the filter (token is valid)
	if filter.MightContain(issuedJTI) {
		t.Error("newly issued JTI should not be in filter")
	}

	// Simulate emergency revocation: add JTI to filter
	filter.Add(issuedJTI)

	// Now the filter should block this token
	if !filter.MightContain(issuedJTI) {
		t.Error("revoked JTI must be detected by filter — no false negatives allowed")
	}

	// Other JTIs should not be affected
	if filter.MightContain("different-jti-456") {
		t.Error("unrelated JTI should not trigger filter (false positive unlikely)")
	}
}

// Integration test: rehydration restores revoked JTIs
func TestEmergencyRevocationFlow_RehydrationRestoresState(t *testing.T) {
	// This test verifies that rehydration restores revoked JTIs:
	// 1. Create a fresh filter (simulating restart)
	// 2. Rehydrate with known revoked JTIs from "DB"
	// 3. Verify filter blocks those JTIs immediately (before pub/sub)

	// Simulate DB contents: these JTIs were revoked before restart
	revokedJTIs := []string{
		"revoked-before-restart-1",
		"revoked-before-restart-2",
		"revoked-before-restart-3",
	}

	// Fresh filter (simulating replica restart)
	filter := oidc.NewBloomRevocationFilter(oidc.DefaultBloomCapacity, oidc.DefaultBloomFPRate)

	// Before rehydration, filter is empty
	for _, jti := range revokedJTIs {
		if filter.MightContain(jti) {
			t.Errorf("fresh filter should not contain %s", jti)
		}
	}

	// Rehydrate from "DB" (simulating startup ListActive → Rehydrate)
	filter.Rehydrate(revokedJTIs)

	// After rehydration, all revoked JTIs must be blocked
	for _, jti := range revokedJTIs {
		if !filter.MightContain(jti) {
			t.Errorf("rehydrated filter must contain %s — no false negatives", jti)
		}
	}

	// New JTIs issued after restart are NOT blocked
	if filter.MightContain("new-jti-after-restart") {
		t.Error("new JTI should not be blocked")
	}
}

// Integration test: false positive triggers DB lookup
func TestEmergencyRevocationFlow_FalsePositiveTriggerDBLookup(t *testing.T) {
	// This test demonstrates the false-positive handling flow:
	// 1. Bloom filter may return true for unknown JTIs (false positive)
	// 2. On MightContain=true, caller must confirm via DB lookup
	// 3. If DB says not revoked, token is valid (false positive case)

	// Create filter with HIGH false-positive rate for demonstration
	// (In production, FP rate is 1/1M; here we use 50% to force hits)
	filter := oidc.NewBloomRevocationFilter(10, 0.5)

	// Add a known revoked JTI
	filter.Add("truly-revoked-jti")

	// Check a truly revoked JTI
	if !filter.MightContain("truly-revoked-jti") {
		t.Fatal("truly revoked JTI must be detected")
	}

	// The verification flow (pseudocode demonstration):
	// 1. filter.MightContain(jti) = true
	// 2. db.GetByJTI(jti) returns (row, found, nil)
	// 3. If found=true → token is revoked (true positive)
	// 4. If found=false → token is valid (false positive)

	// Simulate this flow with mock data:
	type dbLookupResult struct {
		found   bool
		revoked bool
	}

	mockDB := map[string]dbLookupResult{
		"truly-revoked-jti": {found: true, revoked: true},
		"false-positive":    {found: false, revoked: false},
	}

	verifyToken := func(jti string) (isRevoked bool) {
		// Step 1: Bloom filter check (~100ns)
		if !filter.MightContain(jti) {
			return false // Definitely not revoked
		}

		// Step 2: DB introspection (only on filter hit)
		result, ok := mockDB[jti]
		if !ok {
			return false // Not in DB = false positive
		}
		return result.revoked
	}

	// True positive: filter=true, DB=revoked
	if !verifyToken("truly-revoked-jti") {
		t.Error("truly revoked JTI should be blocked")
	}

	// For non-revoked JTIs, verifyToken returns false
	// (either filter=false, or filter=true but DB=not found)
	if verifyToken("definitely-not-revoked") {
		t.Error("non-revoked JTI should not be blocked")
	}
}

// Test all valid reason enum values
func TestValidRevokeReason(t *testing.T) {
	validReasons := []openapi.RevokeJwtRequestReason{
		openapi.EmergencyKill,
		openapi.KeyRotation,
		openapi.UserRequest,
	}

	for _, reason := range validReasons {
		if !validRevokeReason(reason) {
			t.Errorf("expected %q to be valid", reason)
		}
	}

	invalidReasons := []openapi.RevokeJwtRequestReason{
		"",
		"invalid",
		"EMERGENCY_KILL", // case sensitive
		"unknown_reason",
	}

	for _, reason := range invalidReasons {
		if validRevokeReason(reason) {
			t.Errorf("expected %q to be invalid", reason)
		}
	}
}
