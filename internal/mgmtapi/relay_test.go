package mgmtapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/relay"
)

// fakeRelayStore implements RelayStore for testing.
type fakeRelayStore struct {
	addresses     []*relay.Address
	listErr       error
	getErr        error
	deactivateErr error
	deactivatedID string // records the ID passed to the last successful Deactivate call
}

func (f *fakeRelayStore) ListByUser(_ context.Context, userID string) ([]*relay.Address, [][]byte, error) {
	if f.listErr != nil {
		return nil, nil, f.listErr
	}
	// Filter by userID to simulate real behavior
	var result []*relay.Address
	var mappings [][]byte
	for _, a := range f.addresses {
		if uuid.UUID(a.UserID).String() == userID {
			result = append(result, a)
			mappings = append(mappings, []byte("encrypted-mapping"))
		}
	}
	return result, mappings, nil
}

func (f *fakeRelayStore) GetByToken(_ context.Context, token string) (*relay.Address, []byte, error) {
	if f.getErr != nil {
		return nil, nil, f.getErr
	}
	for _, a := range f.addresses {
		if a.Token == token {
			return a, []byte("encrypted-mapping"), nil
		}
	}
	return nil, nil, relay.ErrRelayAddressNotFound
}

func (f *fakeRelayStore) Deactivate(_ context.Context, addressID string) error {
	if f.deactivateErr != nil {
		return f.deactivateErr
	}
	f.deactivatedID = addressID
	return nil
}

func makeTestAddress(userID uuid.UUID, token, clientID string, state relay.State) *relay.Address {
	addr := &relay.Address{
		ID:        uuid.New(),
		Token:     token,
		UserID:    userID,
		ClientID:  clientID,
		State:     state,
		Region:    region.EU,
		CreatedAt: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
	}
	if state == relay.StateDeactivated {
		t := time.Date(2024, 1, 20, 15, 0, 0, 0, time.UTC)
		addr.DeactivatedAt = &t
	}
	return addr
}

func TestGetRelayAddresses_Success(t *testing.T) {
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	store := &fakeRelayStore{
		addresses: []*relay.Address{
			makeTestAddress(userID, "token-abc123", "client-a", relay.StateActive),
			makeTestAddress(userID, "token-xyz789", "client-b", relay.StateDeactivated),
		},
	}

	srv := New(nil, nil).WithRelayStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("GET", "/relay-addresses", nil)
	req.Header.Set(UserIDHeader, userID.String())
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp RelayAddressesListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(resp.Addresses) != 2 {
		t.Fatalf("got %d addresses, want 2", len(resp.Addresses))
	}

	// Check first address
	if resp.Addresses[0].RelayToken != "token-abc123" {
		t.Errorf("addresses[0].relay_token = %q, want %q", resp.Addresses[0].RelayToken, "token-abc123")
	}
	if resp.Addresses[0].State != "active" {
		t.Errorf("addresses[0].state = %q, want %q", resp.Addresses[0].State, "active")
	}
	if resp.Addresses[0].RelayEmail != "token-abc123@relay.EU.harbor.id" {
		t.Errorf("addresses[0].relay_email = %q, want token-abc123@relay.EU.harbor.id", resp.Addresses[0].RelayEmail)
	}

	// Check deactivated address has deactivated_at
	if resp.Addresses[1].State != "deactivated" {
		t.Errorf("addresses[1].state = %q, want %q", resp.Addresses[1].State, "deactivated")
	}
	if resp.Addresses[1].DeactivatedAt == nil {
		t.Error("addresses[1].deactivated_at should be set for deactivated address")
	}
}

func TestGetRelayAddresses_EmptyList(t *testing.T) {
	store := &fakeRelayStore{addresses: nil}

	srv := New(nil, nil).WithRelayStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("GET", "/relay-addresses", nil)
	req.Header.Set(UserIDHeader, "user-with-no-relays")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp RelayAddressesListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(resp.Addresses) != 0 {
		t.Fatalf("got %d addresses, want 0", len(resp.Addresses))
	}
}

func TestGetRelayAddresses_Unauthorized(t *testing.T) {
	store := &fakeRelayStore{}

	srv := New(nil, nil).WithRelayStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	// No X-Harbor-User-ID header
	req := httptest.NewRequest("GET", "/relay-addresses", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	var resp errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Error != "unauthorized" {
		t.Errorf("error = %q, want %q", resp.Error, "unauthorized")
	}
}

func TestGetRelayAddresses_ServiceUnavailable(t *testing.T) {
	// No relay store wired
	srv := New(nil, nil)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("GET", "/relay-addresses", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestGetRelayAddresses_StoreError(t *testing.T) {
	store := &fakeRelayStore{
		listErr: errors.New("database connection failed"),
	}

	srv := New(nil, nil).WithRelayStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("GET", "/relay-addresses", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestGetRelayAddresses_OnlyReturnsOwnAddresses(t *testing.T) {
	userA := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	userB := uuid.MustParse("660e8400-e29b-41d4-a716-446655440000")
	store := &fakeRelayStore{
		addresses: []*relay.Address{
			makeTestAddress(userA, "token-userA", "client-a", relay.StateActive),
			makeTestAddress(userB, "token-userB", "client-b", relay.StateActive),
		},
	}

	srv := New(nil, nil).WithRelayStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	// User A requests their addresses
	req := httptest.NewRequest("GET", "/relay-addresses", nil)
	req.Header.Set(UserIDHeader, userA.String())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp RelayAddressesListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// User A should only see their own address
	if len(resp.Addresses) != 1 {
		t.Fatalf("SECURITY: user A got %d addresses, want 1 (cross-user leakage)", len(resp.Addresses))
	}
	if resp.Addresses[0].RelayToken != "token-userA" {
		t.Errorf("SECURITY: user A received token %q, want token-userA", resp.Addresses[0].RelayToken)
	}
}

func TestDeleteRelayAddress_Success(t *testing.T) {
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	addr := makeTestAddress(userID, "token-to-deactivate", "client-a", relay.StateActive)
	store := &fakeRelayStore{
		addresses: []*relay.Address{addr},
	}

	srv := New(nil, nil).WithRelayStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("DELETE", "/relay-addresses/token-to-deactivate", nil)
	req.Header.Set(UserIDHeader, userID.String())
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if store.deactivatedID != uuid.UUID(addr.ID).String() {
		t.Errorf("deactivated address ID = %q, want %q", store.deactivatedID, uuid.UUID(addr.ID).String())
	}
}

func TestDeleteRelayAddress_NotFound(t *testing.T) {
	store := &fakeRelayStore{addresses: nil}

	srv := New(nil, nil).WithRelayStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("DELETE", "/relay-addresses/nonexistent-token", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestDeleteRelayAddress_Unauthorized(t *testing.T) {
	store := &fakeRelayStore{}

	srv := New(nil, nil).WithRelayStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	// No X-Harbor-User-ID header
	req := httptest.NewRequest("DELETE", "/relay-addresses/some-token", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestDeleteRelayAddress_ServiceUnavailable(t *testing.T) {
	// No relay store wired
	srv := New(nil, nil)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("DELETE", "/relay-addresses/some-token", nil)
	req.Header.Set(UserIDHeader, "user-123")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestDeleteRelayAddress_DeactivateError(t *testing.T) {
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	store := &fakeRelayStore{
		addresses: []*relay.Address{
			makeTestAddress(userID, "token-abc", "client-a", relay.StateActive),
		},
		deactivateErr: errors.New("deactivate failed"),
	}

	srv := New(nil, nil).WithRelayStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("DELETE", "/relay-addresses/token-abc", nil)
	req.Header.Set(UserIDHeader, userID.String())
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// =============================================================================
// Security Tests — Cross-User Relay Isolation
// =============================================================================

// TestSecurity_CrossUserRelayDeactivation verifies that user A cannot deactivate
// user B's relay address via DELETE /relay-addresses/{relay_token}. The endpoint
// must return 404 to avoid leaking existence of other users' relay addresses.
func TestSecurity_CrossUserRelayDeactivation(t *testing.T) {
	userA := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	userB := uuid.MustParse("660e8400-e29b-41d4-a716-446655440000")
	store := &fakeRelayStore{
		addresses: []*relay.Address{
			makeTestAddress(userB, "token-belongs-to-userB", "client-b", relay.StateActive),
		},
	}

	srv := New(nil, nil).WithRelayStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	// User A attempts to deactivate user B's relay address
	req := httptest.NewRequest("DELETE", "/relay-addresses/token-belongs-to-userB", nil)
	req.Header.Set(UserIDHeader, userA.String())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// SECURITY: Must return 404 to avoid leaking existence
	if rec.Code != http.StatusNotFound {
		t.Fatalf("SECURITY: status = %d, want %d (cross-user deactivation should return 404)", rec.Code, http.StatusNotFound)
	}

	// SECURITY: Must NOT have called Deactivate
	if store.deactivatedID != "" {
		t.Errorf("SECURITY: user A deactivated relay %q belonging to user B — cross-user attack", store.deactivatedID)
	}
}

// TestSecurity_CrossUserRelayLeakage_List verifies that user A cannot see
// user B's relay addresses via GET /relay-addresses.
func TestSecurity_CrossUserRelayLeakage_List(t *testing.T) {
	userA := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	userB := uuid.MustParse("660e8400-e29b-41d4-a716-446655440000")
	store := &fakeRelayStore{
		addresses: []*relay.Address{
			makeTestAddress(userA, "token-userA", "client-a", relay.StateActive),
			makeTestAddress(userB, "token-userB", "client-b", relay.StateActive),
		},
	}

	srv := New(nil, nil).WithRelayStore(store)
	mux := http.NewServeMux()
	srv.Routes(mux)

	// User A requests their addresses
	req := httptest.NewRequest("GET", "/relay-addresses", nil)
	req.Header.Set(UserIDHeader, userA.String())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp RelayAddressesListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// SECURITY: User A must only see their own relay, not user B's
	if len(resp.Addresses) != 1 {
		t.Fatalf("SECURITY: user A got %d addresses, want 1 (cross-user leakage)", len(resp.Addresses))
	}
	if resp.Addresses[0].RelayToken != "token-userA" {
		t.Errorf("SECURITY: user A received token %q, want token-userA", resp.Addresses[0].RelayToken)
	}
}

// =============================================================================
// BYO-Domain Tests
// =============================================================================

// fakeBYODomainStore implements BYODomainStore for testing.
type fakeBYODomainStore struct {
	domains   map[string]*relay.BYODomain // keyed by domain name
	createErr error
	getErr    error
	listErr   error
	updateErr error
	deleteErr error
	deletedID string
}

func newFakeBYODomainStore() *fakeBYODomainStore {
	return &fakeBYODomainStore{
		domains: make(map[string]*relay.BYODomain),
	}
}

func (f *fakeBYODomainStore) CreateDomain(_ context.Context, domain *relay.BYODomain) error {
	if f.createErr != nil {
		return f.createErr
	}
	if _, exists := f.domains[domain.Domain]; exists {
		return relay.ErrDomainAlreadyExists
	}
	f.domains[domain.Domain] = domain
	return nil
}

func (f *fakeBYODomainStore) GetDomainByName(_ context.Context, userID, domain string) (*relay.BYODomain, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	d, ok := f.domains[domain]
	if !ok {
		return nil, relay.ErrDomainNotFound
	}
	// Check ownership
	if d.UserID.String() != userID {
		return nil, relay.ErrDomainNotFound
	}
	return d, nil
}

func (f *fakeBYODomainStore) ListDomainsByUser(_ context.Context, userID string) ([]*relay.BYODomain, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var result []*relay.BYODomain
	for _, d := range f.domains {
		if d.UserID.String() == userID {
			result = append(result, d)
		}
	}
	return result, nil
}

func (f *fakeBYODomainStore) UpdateDomainState(_ context.Context, domainID string, state relay.BYODomainState) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	for _, d := range f.domains {
		if d.ID.String() == domainID {
			d.State = state
			return nil
		}
	}
	return relay.ErrDomainNotFound
}

func (f *fakeBYODomainStore) DeleteDomain(_ context.Context, domainID string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	for name, d := range f.domains {
		if d.ID.String() == domainID {
			f.deletedID = domainID
			delete(f.domains, name)
			return nil
		}
	}
	return relay.ErrDomainNotFound
}

func TestPostBYODomain_Success(t *testing.T) {
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	store := newFakeBYODomainStore()

	srv := New(nil, nil).WithBYODomainStore(store, nil, "mta-eu.harbor.id", "relay.eu.harbor.id")
	mux := http.NewServeMux()
	srv.Routes(mux)

	body := `{"domain": "mail.example.com"}`
	req := httptest.NewRequest("POST", "/byo-domains", bytes.NewBufferString(body))
	req.Header.Set(UserIDHeader, userID.String())
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp BYODomainResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Domain != "mail.example.com" {
		t.Errorf("domain = %q, want %q", resp.Domain, "mail.example.com")
	}
	if resp.State != "pending" {
		t.Errorf("state = %q, want %q", resp.State, "pending")
	}
	if resp.TXTRecord == "" {
		t.Error("txt_record should be set for pending domain")
	}
	if resp.MXRecord == "" {
		t.Error("mx_record should be set")
	}
	if resp.SPFRecord == "" {
		t.Error("spf_record should be set")
	}
	if resp.DKIMRecord == "" {
		t.Error("dkim_record should be set")
	}
}

func TestPostBYODomain_Unauthorized(t *testing.T) {
	store := newFakeBYODomainStore()
	srv := New(nil, nil).WithBYODomainStore(store, nil, "mta-eu.harbor.id", "relay.eu.harbor.id")
	mux := http.NewServeMux()
	srv.Routes(mux)

	body := `{"domain": "mail.example.com"}`
	req := httptest.NewRequest("POST", "/byo-domains", bytes.NewBufferString(body))
	// No user ID header
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestPostBYODomain_InvalidDomain(t *testing.T) {
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	store := newFakeBYODomainStore()

	srv := New(nil, nil).WithBYODomainStore(store, nil, "mta-eu.harbor.id", "relay.eu.harbor.id")
	mux := http.NewServeMux()
	srv.Routes(mux)

	body := `{"domain": "invalid"}`
	req := httptest.NewRequest("POST", "/byo-domains", bytes.NewBufferString(body))
	req.Header.Set(UserIDHeader, userID.String())
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestPostBYODomain_ServiceUnavailable(t *testing.T) {
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	// No BYO-domain store configured
	srv := New(nil, nil)
	mux := http.NewServeMux()
	srv.Routes(mux)

	body := `{"domain": "mail.example.com"}`
	req := httptest.NewRequest("POST", "/byo-domains", bytes.NewBufferString(body))
	req.Header.Set(UserIDHeader, userID.String())
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestGetBYODomains_Success(t *testing.T) {
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	store := newFakeBYODomainStore()

	// Add a domain for the user
	domain := &relay.BYODomain{
		ID:             uuid.New(),
		Domain:         "mail.example.com",
		UserID:         userID,
		ChallengeToken: "test-token",
		State:          relay.BYODomainStatePending,
		Region:         region.EU,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(72 * time.Hour),
	}
	store.domains["mail.example.com"] = domain

	srv := New(nil, nil).WithBYODomainStore(store, nil, "mta-eu.harbor.id", "relay.eu.harbor.id")
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("GET", "/byo-domains", nil)
	req.Header.Set(UserIDHeader, userID.String())
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp BYODomainsListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(resp.Domains) != 1 {
		t.Fatalf("got %d domains, want 1", len(resp.Domains))
	}
	if resp.Domains[0].Domain != "mail.example.com" {
		t.Errorf("domain = %q, want %q", resp.Domains[0].Domain, "mail.example.com")
	}
}

func TestDeleteBYODomain_Success(t *testing.T) {
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	store := newFakeBYODomainStore()

	// Add a domain for the user
	domainID := uuid.New()
	domain := &relay.BYODomain{
		ID:             domainID,
		Domain:         "mail.example.com",
		UserID:         userID,
		ChallengeToken: "test-token",
		State:          relay.BYODomainStatePending,
		Region:         region.EU,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(72 * time.Hour),
	}
	store.domains["mail.example.com"] = domain

	srv := New(nil, nil).WithBYODomainStore(store, nil, "mta-eu.harbor.id", "relay.eu.harbor.id")
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("DELETE", "/byo-domains/mail.example.com", nil)
	req.Header.Set(UserIDHeader, userID.String())
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	if store.deletedID != domainID.String() {
		t.Errorf("deleted ID = %q, want %q", store.deletedID, domainID.String())
	}
}

func TestDeleteBYODomain_NotFound(t *testing.T) {
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	store := newFakeBYODomainStore()

	srv := New(nil, nil).WithBYODomainStore(store, nil, "mta-eu.harbor.id", "relay.eu.harbor.id")
	mux := http.NewServeMux()
	srv.Routes(mux)

	req := httptest.NewRequest("DELETE", "/byo-domains/nonexistent.example.com", nil)
	req.Header.Set(UserIDHeader, userID.String())
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// TestSecurity_CrossUserBYODomainAccess verifies that user A cannot access
// user B's BYO-domains.
func TestSecurity_CrossUserBYODomainAccess(t *testing.T) {
	userA := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	userB := uuid.MustParse("660e8400-e29b-41d4-a716-446655440000")
	store := newFakeBYODomainStore()

	// Add a domain for user B
	store.domains["userb-domain.example.com"] = &relay.BYODomain{
		ID:             uuid.New(),
		Domain:         "userb-domain.example.com",
		UserID:         userB,
		ChallengeToken: "test-token",
		State:          relay.BYODomainStatePending,
		Region:         region.EU,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(72 * time.Hour),
	}

	srv := New(nil, nil).WithBYODomainStore(store, nil, "mta-eu.harbor.id", "relay.eu.harbor.id")
	mux := http.NewServeMux()
	srv.Routes(mux)

	// User A tries to delete user B's domain
	req := httptest.NewRequest("DELETE", "/byo-domains/userb-domain.example.com", nil)
	req.Header.Set(UserIDHeader, userA.String())
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	// SECURITY: Must return 404 to avoid leaking existence
	if rec.Code != http.StatusNotFound {
		t.Fatalf("SECURITY: status = %d, want %d (cross-user access should return 404)", rec.Code, http.StatusNotFound)
	}

	// SECURITY: Domain must NOT have been deleted
	if _, exists := store.domains["userb-domain.example.com"]; !exists {
		t.Error("SECURITY: user A deleted user B's domain — cross-user attack")
	}
}

// TestSecurity_CrossUserBYODomainList verifies that user A cannot see
// user B's BYO-domains via GET /byo-domains.
func TestSecurity_CrossUserBYODomainList(t *testing.T) {
	userA := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	userB := uuid.MustParse("660e8400-e29b-41d4-a716-446655440000")
	store := newFakeBYODomainStore()

	// Add domains for both users
	store.domains["usera-domain.example.com"] = &relay.BYODomain{
		ID:        uuid.New(),
		Domain:    "usera-domain.example.com",
		UserID:    userA,
		State:     relay.BYODomainStatePending,
		Region:    region.EU,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(72 * time.Hour),
	}
	store.domains["userb-domain.example.com"] = &relay.BYODomain{
		ID:        uuid.New(),
		Domain:    "userb-domain.example.com",
		UserID:    userB,
		State:     relay.BYODomainStatePending,
		Region:    region.EU,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(72 * time.Hour),
	}

	srv := New(nil, nil).WithBYODomainStore(store, nil, "mta-eu.harbor.id", "relay.eu.harbor.id")
	mux := http.NewServeMux()
	srv.Routes(mux)

	// User A requests their domains
	req := httptest.NewRequest("GET", "/byo-domains", nil)
	req.Header.Set(UserIDHeader, userA.String())
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp BYODomainsListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// SECURITY: User A must only see their own domain
	if len(resp.Domains) != 1 {
		t.Fatalf("SECURITY: user A got %d domains, want 1 (cross-user leakage)", len(resp.Domains))
	}
	if resp.Domains[0].Domain != "usera-domain.example.com" {
		t.Errorf("SECURITY: user A received domain %q, want usera-domain.example.com", resp.Domains[0].Domain)
	}
}
