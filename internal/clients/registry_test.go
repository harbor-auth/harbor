package clients

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/oidc"
)

// fakeRPQuerier is a minimal rpQuerier fake for unit tests.
type fakeRPQuerier struct {
	rows map[string]db.RelyingParty
}

func newFakeRPQuerier(rows ...db.RelyingParty) *fakeRPQuerier {
	m := make(map[string]db.RelyingParty, len(rows))
	for _, r := range rows {
		m[r.ClientID] = r
	}
	return &fakeRPQuerier{rows: m}
}

func (f *fakeRPQuerier) GetRelyingParty(_ context.Context, clientID string) (db.RelyingParty, error) {
	r, ok := f.rows[clientID]
	if !ok {
		return db.RelyingParty{}, pgx.ErrNoRows
	}
	return r, nil
}

func TestRowToClient(t *testing.T) {
	row := db.RelyingParty{
		ClientID:      "rp-1",
		Name:          "Test RP",
		SectorID:      "sector.example.com",
		RedirectUris:  []string{"https://rp.example.com/cb"},
		LogoutUris:    []string{"https://rp.example.com/logged-out"},
		TokenFormat:   "jwt",
		ScopesAllowed: []string{"openid", "profile"},
	}
	c := rowToClient(row)
	if c.ID != row.ClientID {
		t.Errorf("ID: got %q, want %q", c.ID, row.ClientID)
	}
	if c.SectorID != row.SectorID {
		t.Errorf("SectorID: got %q, want %q", c.SectorID, row.SectorID)
	}
	if len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != row.RedirectUris[0] {
		t.Errorf("RedirectURIs mismatch")
	}
	if len(c.LogoutURIs) != 1 || c.LogoutURIs[0] != row.LogoutUris[0] {
		t.Errorf("LogoutURIs mismatch")
	}
	if len(c.ScopesAllowed) != 2 {
		t.Errorf("ScopesAllowed: got %d, want 2", len(c.ScopesAllowed))
	}
}

func TestDBClientRegistryLookupFound(t *testing.T) {
	reg := NewDBClientRegistry(newFakeRPQuerier(db.RelyingParty{
		ClientID:      "my-rp",
		SectorID:      "sector.example.com",
		RedirectUris:  []string{"https://rp.example.com/cb"},
		ScopesAllowed: []string{"openid"},
	}))
	c, ok := reg.Lookup(context.Background(), "my-rp")
	if !ok {
		t.Fatal("expected found=true")
	}
	if c.ID != "my-rp" {
		t.Errorf("client ID: got %q, want %q", c.ID, "my-rp")
	}
}

func TestDBClientRegistryLookupUnknown(t *testing.T) {
	reg := NewDBClientRegistry(newFakeRPQuerier())
	_, ok := reg.Lookup(context.Background(), "unknown")
	if ok {
		t.Fatal("expected found=false for unknown client")
	}
}

//harbor:invariant INV-DB-CLIENT-ERROR-NOT-REDIRECTED
func TestDBClientRegistryLookupDBError(t *testing.T) {
	// A non-ErrNoRows DB error must return found=false (open-redirect defence).
	f := &errRPQuerier{err: errors.New("connection reset")}
	reg := NewDBClientRegistry(f)
	_, ok := reg.Lookup(context.Background(), "any")
	if ok {
		t.Fatal("expected found=false on DB error (open-redirect defence)")
	}
}

type errRPQuerier struct{ err error }

func (e *errRPQuerier) GetRelyingParty(_ context.Context, _ string) (db.RelyingParty, error) {
	return db.RelyingParty{}, e.err
}

func TestRedirectURIExactMatch(t *testing.T) {
	row := db.RelyingParty{
		ClientID:      "rp-2",
		RedirectUris:  []string{"https://rp.example.com/callback"},
		ScopesAllowed: []string{"openid"},
	}
	c := rowToClient(row)
	if !c.HasRedirectURI("https://rp.example.com/callback") {
		t.Error("exact URI should match")
	}
	if c.HasRedirectURI("https://rp.example.com/callback/") {
		t.Error("trailing slash must not match (exact-match invariant)")
	}
	if c.HasRedirectURI("https://rp.example.com") {
		t.Error("prefix must not match (exact-match invariant)")
	}
}

func TestLogoutURIExactMatch(t *testing.T) {
	row := db.RelyingParty{
		ClientID:     "rp-3",
		LogoutUris:   []string{"https://rp.example.com/logged-out"},
	}
	c := rowToClient(row)
	if !c.HasLogoutURI("https://rp.example.com/logged-out") {
		t.Error("exact logout URI should match")
	}
	if c.HasLogoutURI("https://rp.example.com/logged-out/") {
		t.Error("trailing slash must not match (exact-match invariant)")
	}
	if c.HasLogoutURI("https://rp.example.com") {
		t.Error("prefix must not match (exact-match invariant)")
	}
	if c.HasLogoutURI("https://evil.example.com/logged-out") {
		t.Error("different domain must not match (open-redirect defence)")
	}
}

func TestDBClientRegistryImplementsInterface(t *testing.T) {
	var _ oidc.ClientRegistry = (*DBClientRegistry)(nil)
}
