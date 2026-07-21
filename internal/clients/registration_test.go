package clients

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor/harbor/internal/gen/db"
)

// fakeRegistrationQuerier is a minimal registrationQuerier fake for unit tests.
type fakeRegistrationQuerier struct {
	clients map[string]db.RelyingParty
	// tokenIndex maps registration_access_token_hash to client_id for lookups.
	tokenIndex map[string]string
}

func newFakeRegistrationQuerier() *fakeRegistrationQuerier {
	return &fakeRegistrationQuerier{
		clients:    make(map[string]db.RelyingParty),
		tokenIndex: make(map[string]string),
	}
}

func (f *fakeRegistrationQuerier) CreateRegisteredClient(_ context.Context, arg db.CreateRegisteredClientParams) (db.RelyingParty, error) {
	if _, exists := f.clients[arg.ClientID]; exists {
		return db.RelyingParty{}, errors.New("client already exists")
	}
	//nolint:staticcheck // explicit field mapping documents the params→row shape for readers
	rp := db.RelyingParty{
		ClientID:                    arg.ClientID,
		Name:                        arg.Name,
		SectorID:                    arg.SectorID,
		RedirectUris:                arg.RedirectUris,
		TokenFormat:                 arg.TokenFormat,
		ScopesAllowed:               arg.ScopesAllowed,
		ClientSecretHash:            arg.ClientSecretHash,
		RegistrationAccessTokenHash: arg.RegistrationAccessTokenHash,
		GrantTypes:                  arg.GrantTypes,
		ResponseTypes:               arg.ResponseTypes,
		TokenEndpointAuthMethod:     arg.TokenEndpointAuthMethod,
		CreatedAt:                   arg.CreatedAt,
	}
	f.clients[arg.ClientID] = rp
	if len(arg.RegistrationAccessTokenHash) > 0 {
		f.tokenIndex[string(arg.RegistrationAccessTokenHash)] = arg.ClientID
	}
	return rp, nil
}

func (f *fakeRegistrationQuerier) GetRegisteredClient(_ context.Context, registrationAccessTokenHash []byte) (db.RelyingParty, error) {
	clientID, ok := f.tokenIndex[string(registrationAccessTokenHash)]
	if !ok {
		return db.RelyingParty{}, pgx.ErrNoRows
	}
	return f.clients[clientID], nil
}

func (f *fakeRegistrationQuerier) GetRelyingParty(_ context.Context, clientID string) (db.RelyingParty, error) {
	rp, ok := f.clients[clientID]
	if !ok {
		return db.RelyingParty{}, pgx.ErrNoRows
	}
	return rp, nil
}

func (f *fakeRegistrationQuerier) UpdateRegisteredClient(_ context.Context, arg db.UpdateRegisteredClientParams) (db.RelyingParty, error) {
	rp, ok := f.clients[arg.ClientID]
	if !ok {
		return db.RelyingParty{}, pgx.ErrNoRows
	}
	// Remove old token from index.
	if len(rp.RegistrationAccessTokenHash) > 0 {
		delete(f.tokenIndex, string(rp.RegistrationAccessTokenHash))
	}
	// Update fields (sector_id and created_at remain unchanged).
	rp.Name = arg.Name
	rp.RedirectUris = arg.RedirectUris
	rp.TokenFormat = arg.TokenFormat
	rp.ScopesAllowed = arg.ScopesAllowed
	rp.ClientSecretHash = arg.ClientSecretHash
	rp.RegistrationAccessTokenHash = arg.RegistrationAccessTokenHash
	rp.GrantTypes = arg.GrantTypes
	rp.ResponseTypes = arg.ResponseTypes
	rp.TokenEndpointAuthMethod = arg.TokenEndpointAuthMethod
	f.clients[arg.ClientID] = rp
	// Add new token to index.
	if len(arg.RegistrationAccessTokenHash) > 0 {
		f.tokenIndex[string(arg.RegistrationAccessTokenHash)] = arg.ClientID
	}
	return rp, nil
}

func (f *fakeRegistrationQuerier) DeleteRelyingParty(_ context.Context, clientID string) error {
	rp, ok := f.clients[clientID]
	if ok && len(rp.RegistrationAccessTokenHash) > 0 {
		delete(f.tokenIndex, string(rp.RegistrationAccessTokenHash))
	}
	delete(f.clients, clientID)
	return nil
}

func TestDBClientRegistrationStoreCreate(t *testing.T) {
	fake := newFakeRegistrationQuerier()
	store := NewDBClientRegistrationStore(fake)

	now := time.Now().Truncate(time.Microsecond)
	tokenHash := sha256.Sum256([]byte("reg-token-123"))

	c, err := store.Create(context.Background(), NewRegisteredClient{
		ClientID:                    "dyn-client-1",
		Name:                        "Dynamic Client",
		SectorID:                    "sector.example.com",
		RedirectURIs:                []string{"https://client.example.com/cb"},
		TokenFormat:                 "jwt",
		ScopesAllowed:               []string{"openid", "profile"},
		ClientSecretHash:            []byte("secret-hash"),
		RegistrationAccessTokenHash: tokenHash[:],
		GrantTypes:                  []string{"authorization_code", "refresh_token"},
		ResponseTypes:               []string{"code"},
		TokenEndpointAuthMethod:     "client_secret_basic",
		CreatedAt:                   now,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if c.ClientID != "dyn-client-1" {
		t.Errorf("ClientID: got %q, want %q", c.ClientID, "dyn-client-1")
	}
	if c.Name != "Dynamic Client" {
		t.Errorf("Name: got %q, want %q", c.Name, "Dynamic Client")
	}
	if c.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Errorf("TokenEndpointAuthMethod: got %q, want %q", c.TokenEndpointAuthMethod, "client_secret_basic")
	}
	if len(c.GrantTypes) != 2 {
		t.Errorf("GrantTypes: got %d, want 2", len(c.GrantTypes))
	}
}

func TestDBClientRegistrationStoreGet(t *testing.T) {
	fake := newFakeRegistrationQuerier()
	store := NewDBClientRegistrationStore(fake)

	// Seed a client.
	tokenHash := sha256.Sum256([]byte("token"))
	var createdAt pgtype.Timestamptz
	if err := createdAt.Scan(time.Now()); err != nil {
		t.Fatalf("scan createdAt: %v", err)
	}
	fake.clients["existing-client"] = db.RelyingParty{
		ClientID:                    "existing-client",
		Name:                        "Existing",
		SectorID:                    "sector.example.com",
		RedirectUris:                []string{"https://example.com/cb"},
		TokenFormat:                 "jwt",
		ScopesAllowed:               []string{"openid"},
		RegistrationAccessTokenHash: tokenHash[:],
		CreatedAt:                   createdAt,
	}

	c, err := store.Get(context.Background(), "existing-client")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if c.ClientID != "existing-client" {
		t.Errorf("ClientID: got %q, want %q", c.ClientID, "existing-client")
	}
}

func TestDBClientRegistrationStoreGetNotFound(t *testing.T) {
	fake := newFakeRegistrationQuerier()
	store := NewDBClientRegistrationStore(fake)

	_, err := store.Get(context.Background(), "nonexistent")
	if !errors.Is(err, ErrClientNotFound) {
		t.Errorf("expected ErrClientNotFound, got %v", err)
	}
}

func TestDBClientRegistrationStoreVerifyRegToken(t *testing.T) {
	fake := newFakeRegistrationQuerier()
	store := NewDBClientRegistrationStore(fake)

	// Create a client with a known token.
	token := "my-reg-access-token"
	tokenHash := sha256.Sum256([]byte(token))
	var createdAt pgtype.Timestamptz
	if err := createdAt.Scan(time.Now()); err != nil {
		t.Fatalf("scan createdAt: %v", err)
	}

	fake.clients["token-client"] = db.RelyingParty{
		ClientID:                    "token-client",
		Name:                        "Token Client",
		SectorID:                    "sector.example.com",
		RedirectUris:                []string{"https://example.com/cb"},
		TokenFormat:                 "jwt",
		ScopesAllowed:               []string{"openid"},
		RegistrationAccessTokenHash: tokenHash[:],
		CreatedAt:                   createdAt,
	}
	fake.tokenIndex[string(tokenHash[:])] = "token-client"

	c, err := store.VerifyRegToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyRegToken failed: %v", err)
	}
	if c.ClientID != "token-client" {
		t.Errorf("ClientID: got %q, want %q", c.ClientID, "token-client")
	}
}

func TestDBClientRegistrationStoreVerifyRegTokenInvalid(t *testing.T) {
	fake := newFakeRegistrationQuerier()
	store := NewDBClientRegistrationStore(fake)

	// No clients exist, so any token is invalid.
	_, err := store.VerifyRegToken(context.Background(), "invalid-token")
	if !errors.Is(err, ErrInvalidRegToken) {
		t.Errorf("expected ErrInvalidRegToken, got %v", err)
	}
}

func TestDBClientRegistrationStoreVerifyRegTokenEmpty(t *testing.T) {
	fake := newFakeRegistrationQuerier()
	store := NewDBClientRegistrationStore(fake)

	_, err := store.VerifyRegToken(context.Background(), "")
	if !errors.Is(err, ErrInvalidRegToken) {
		t.Errorf("expected ErrInvalidRegToken for empty token, got %v", err)
	}
}

func TestDBClientRegistrationStoreUpdate(t *testing.T) {
	fake := newFakeRegistrationQuerier()
	store := NewDBClientRegistrationStore(fake)

	// Seed a client.
	originalTokenHash := sha256.Sum256([]byte("original-token"))
	var createdAt pgtype.Timestamptz
	if err := createdAt.Scan(time.Now()); err != nil {
		t.Fatalf("scan createdAt: %v", err)
	}

	fake.clients["update-client"] = db.RelyingParty{
		ClientID:                    "update-client",
		Name:                        "Original Name",
		SectorID:                    "sector.example.com",
		RedirectUris:                []string{"https://example.com/cb"},
		TokenFormat:                 "jwt",
		ScopesAllowed:               []string{"openid"},
		RegistrationAccessTokenHash: originalTokenHash[:],
		CreatedAt:                   createdAt,
	}
	fake.tokenIndex[string(originalTokenHash[:])] = "update-client"

	newTokenHash := sha256.Sum256([]byte("new-token"))
	c, err := store.Update(context.Background(), UpdateRegisteredClient{
		ClientID:                    "update-client",
		Name:                        "Updated Name",
		RedirectURIs:                []string{"https://new.example.com/cb"},
		TokenFormat:                 "opaque",
		ScopesAllowed:               []string{"openid", "email"},
		RegistrationAccessTokenHash: newTokenHash[:],
		GrantTypes:                  []string{"authorization_code"},
		ResponseTypes:               []string{"code"},
		TokenEndpointAuthMethod:     "client_secret_post",
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if c.Name != "Updated Name" {
		t.Errorf("Name: got %q, want %q", c.Name, "Updated Name")
	}
	if c.TokenFormat != "opaque" {
		t.Errorf("TokenFormat: got %q, want %q", c.TokenFormat, "opaque")
	}
	if c.TokenEndpointAuthMethod != "client_secret_post" {
		t.Errorf("TokenEndpointAuthMethod: got %q, want %q", c.TokenEndpointAuthMethod, "client_secret_post")
	}
	// Verify sector_id is preserved (immutable).
	if c.SectorID != "sector.example.com" {
		t.Errorf("SectorID should be immutable: got %q, want %q", c.SectorID, "sector.example.com")
	}
}

func TestDBClientRegistrationStoreUpdateNotFound(t *testing.T) {
	fake := newFakeRegistrationQuerier()
	store := NewDBClientRegistrationStore(fake)

	_, err := store.Update(context.Background(), UpdateRegisteredClient{
		ClientID: "nonexistent",
		Name:     "Whatever",
	})
	if !errors.Is(err, ErrClientNotFound) {
		t.Errorf("expected ErrClientNotFound, got %v", err)
	}
}

func TestDBClientRegistrationStoreDelete(t *testing.T) {
	fake := newFakeRegistrationQuerier()
	store := NewDBClientRegistrationStore(fake)

	// Seed a client.
	tokenHash := sha256.Sum256([]byte("token"))
	fake.clients["delete-client"] = db.RelyingParty{
		ClientID:                    "delete-client",
		Name:                        "To Delete",
		RegistrationAccessTokenHash: tokenHash[:],
	}
	fake.tokenIndex[string(tokenHash[:])] = "delete-client"

	err := store.Delete(context.Background(), "delete-client")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify client is gone.
	_, err = store.Get(context.Background(), "delete-client")
	if !errors.Is(err, ErrClientNotFound) {
		t.Errorf("expected ErrClientNotFound after delete, got %v", err)
	}

	// Verify token index is cleaned up.
	_, err = store.VerifyRegToken(context.Background(), "token")
	if !errors.Is(err, ErrInvalidRegToken) {
		t.Errorf("expected ErrInvalidRegToken after delete, got %v", err)
	}
}

func TestDBClientRegistrationStoreDeleteIdempotent(t *testing.T) {
	fake := newFakeRegistrationQuerier()
	store := NewDBClientRegistrationStore(fake)

	// Deleting a nonexistent client should not error (idempotent).
	err := store.Delete(context.Background(), "nonexistent")
	if err != nil {
		t.Errorf("Delete should be idempotent, got error: %v", err)
	}
}

func TestRowToRegisteredClient(t *testing.T) {
	now := time.Now().Truncate(time.Microsecond)
	var createdAt pgtype.Timestamptz
	if err := createdAt.Scan(now); err != nil {
		t.Fatalf("scan createdAt: %v", err)
	}

	authMethod := "client_secret_basic"
	row := db.RelyingParty{
		ClientID:                    "test-client",
		Name:                        "Test Client",
		SectorID:                    "sector.example.com",
		RedirectUris:                []string{"https://example.com/cb"},
		TokenFormat:                 "jwt",
		ScopesAllowed:               []string{"openid", "profile"},
		ClientSecretHash:            []byte("secret-hash"),
		RegistrationAccessTokenHash: []byte("token-hash"),
		GrantTypes:                  []string{"authorization_code"},
		ResponseTypes:               []string{"code"},
		TokenEndpointAuthMethod:     &authMethod,
		CreatedAt:                   createdAt,
	}

	c := rowToRegisteredClient(row)

	if c.ClientID != "test-client" {
		t.Errorf("ClientID: got %q, want %q", c.ClientID, "test-client")
	}
	if c.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Errorf("TokenEndpointAuthMethod: got %q, want %q", c.TokenEndpointAuthMethod, "client_secret_basic")
	}
	if !c.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt: got %v, want %v", c.CreatedAt, now)
	}
}

func TestRowToRegisteredClientNilAuthMethod(t *testing.T) {
	row := db.RelyingParty{
		ClientID:                "test-client",
		TokenEndpointAuthMethod: nil, // NULL in DB
	}

	c := rowToRegisteredClient(row)

	if c.TokenEndpointAuthMethod != "" {
		t.Errorf("TokenEndpointAuthMethod should be empty for nil, got %q", c.TokenEndpointAuthMethod)
	}
}
