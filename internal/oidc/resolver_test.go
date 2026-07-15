package oidc

import (
	"context"
	"errors"
	"testing"
)

// resolverTestSecret returns a deterministic 32-byte pairwise secret for tests.
func resolverTestSecret() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

// resolverTestClient builds a Client with a sector_id for PPID derivation.
func resolverTestClient(id, sector string) Client {
	return Client{ID: id, SectorID: sector, ScopesAllowed: []string{"openid", "profile"}}
}

// newTestResolver wires a PPIDSessionResolver over in-memory collaborators, with
// the user's pairwise secret pre-seeded. Returns the resolver and its grant
// store so tests can inspect recorded grants.
func newTestResolver(t *testing.T, userID string, secret []byte) (*PPIDSessionResolver, *InMemoryGrantStore) {
	t.Helper()
	loader := NewInMemorySecretLoader()
	loader.Put(userID, UserSecret{Region: "us", Secret: secret})
	grants := NewInMemoryGrantStore()
	r := NewPPIDSessionResolver(PPIDSessionResolverConfig{
		Auth:   NewFixedAuthSource(userID),
		Loader: loader,
		Grants: grants,
	})
	return r, grants
}

//harbor:invariant INV-SESSION-PPID-STABLE
func TestPPIDSessionResolverStableSubject(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	r, _ := newTestResolver(t, userID, resolverTestSecret())
	client := resolverTestClient("rp-a", "rp-a.example.com")

	sub1, uid1, approved1, err := r.Resolve(context.Background(), client, "openid")
	if err != nil || !approved1 || sub1 == "" {
		t.Fatalf("first Resolve: sub=%q uid=%q approved=%v err=%v", sub1, uid1, approved1, err)
	}
	if uid1 != userID {
		t.Fatalf("userID: got %q, want %q", uid1, userID)
	}

	sub2, uid2, approved2, err := r.Resolve(context.Background(), client, "openid")
	if err != nil || !approved2 {
		t.Fatalf("second Resolve: approved=%v err=%v", approved2, err)
	}
	if sub1 != sub2 {
		t.Fatalf("subject not stable across calls: %q != %q", sub1, sub2)
	}
	if uid1 != uid2 {
		t.Fatalf("userID not stable across calls: %q != %q", uid1, uid2)
	}
}

//harbor:invariant INV-SESSION-PPID-UNLINKABLE
func TestPPIDSessionResolverUnlinkability(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	r, _ := newTestResolver(t, userID, resolverTestSecret())

	subA, _, _, err := r.Resolve(context.Background(), resolverTestClient("rp-a", "rp-a.example.com"), "openid")
	if err != nil {
		t.Fatalf("Resolve rp-a: %v", err)
	}
	subB, _, _, err := r.Resolve(context.Background(), resolverTestClient("rp-b", "rp-b.example.com"), "openid")
	if err != nil {
		t.Fatalf("Resolve rp-b: %v", err)
	}
	if subA == subB {
		t.Fatal("different sectors must yield different PPIDs (cross-RP correlation must be impossible)")
	}
}

//harbor:invariant INV-SESSION-PPID-NO-RAW-UID
func TestPPIDSessionResolverFailClosed(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"

	// Loader has NO secret for the user -> LoadUserSecret fails. Resolve must
	// return an empty subject and a non-nil error, never the raw userID.
	loader := NewInMemorySecretLoader()
	r := NewPPIDSessionResolver(PPIDSessionResolverConfig{
		Auth:   NewFixedAuthSource(userID),
		Loader: loader,
		Grants: NewInMemoryGrantStore(),
	})

	sub, uid, approved, err := r.Resolve(context.Background(), resolverTestClient("rp-a", "rp-a.example.com"), "openid")
	if err == nil {
		t.Fatal("expected an error when the pairwise secret cannot be loaded")
	}
	if approved {
		t.Fatal("must not approve when resolution fails")
	}
	if sub != "" {
		t.Fatalf("subject must be empty on failure, got %q", sub)
	}
	if sub == userID || uid == userID {
		t.Fatal("raw user_id must never be returned as the subject on an error path")
	}
}

func TestPPIDSessionResolverGrantReuse(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	r, grants := newTestResolver(t, userID, resolverTestSecret())
	client := resolverTestClient("rp-a", "rp-a.example.com")

	if _, _, _, err := r.Resolve(context.Background(), client, "openid profile"); err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	if _, _, _, err := r.Resolve(context.Background(), client, "openid profile"); err != nil {
		t.Fatalf("second Resolve: %v", err)
	}

	list, err := grants.ListGrantsByUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListGrantsByUser: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected exactly one grant reused across Resolve calls, got %d", len(list))
	}
}

// TestPPIDSessionResolverScopeExpansion verifies that re-consenting with a
// superset of scopes (e.g. adding offline_access) upgrades the grant without
// changing the stable PPID. This is the root-cause fix for the e2e
// TestAuthorizeTokenRefreshFlow CI failure: test 1 creates a grant with
// "openid" only; test 2 re-authorizes with "openid offline_access" — the
// grant must be upgraded so Refresh() sees offline_access in grant.Scopes.
func TestPPIDSessionResolverScopeExpansion(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	r, grants := newTestResolver(t, userID, resolverTestSecret())
	client := resolverTestClient("rp-a", "rp-a.example.com")

	// First consent: openid only.
	sub1, _, _, err := r.Resolve(context.Background(), client, "openid")
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}

	// Second consent: openid + offline_access (scope upgrade).
	sub2, _, _, err := r.Resolve(context.Background(), client, "openid offline_access")
	if err != nil {
		t.Fatalf("second Resolve (scope upgrade): %v", err)
	}

	// PPID must be stable across re-authorizations.
	if sub1 != sub2 {
		t.Fatalf("PPID changed across scope upgrade: %q != %q", sub1, sub2)
	}

	// The grant must now include offline_access.
	list, err := grants.ListGrantsByUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListGrantsByUser: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected exactly one active grant after scope upgrade, got %d", len(list))
	}
	scopeSet := make(map[string]bool, len(list[0].Scopes))
	for _, s := range list[0].Scopes {
		scopeSet[s] = true
	}
	if !scopeSet["offline_access"] {
		t.Fatalf("upgraded grant must contain offline_access; got scopes = %v", list[0].Scopes)
	}
	if !scopeSet["openid"] {
		t.Fatalf("upgraded grant must retain openid; got scopes = %v", list[0].Scopes)
	}
}

// TestPPIDSessionResolverScopeExpansionPreservesGrantCount verifies that a
// scope upgrade produces exactly one active grant (the old one is revoked and
// a new one is created — net count stays at 1, not 2).
func TestPPIDSessionResolverScopeExpansionPreservesGrantCount(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	r, grants := newTestResolver(t, userID, resolverTestSecret())
	client := resolverTestClient("rp-a", "rp-a.example.com")

	// Three resolve calls, each adding a new scope.
	for _, scope := range []string{"openid", "openid profile", "openid profile offline_access"} {
		if _, _, _, err := r.Resolve(context.Background(), client, scope); err != nil {
			t.Fatalf("Resolve(%q): %v", scope, err)
		}
	}

	list, err := grants.ListGrantsByUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListGrantsByUser: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected exactly one active grant after 3 upgrades, got %d", len(list))
	}
	if len(list[0].Scopes) != 3 {
		t.Fatalf("expected 3 scopes after full expansion, got %v", list[0].Scopes)
	}
}

func TestPPIDSessionResolverNoSectorFailsClosed(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	r, _ := newTestResolver(t, userID, resolverTestSecret())
	client := resolverTestClient("rp-no-sector", "") // empty sector_id

	sub, _, approved, err := r.Resolve(context.Background(), client, "openid")
	if err == nil {
		t.Fatal("expected an error when the client has no sector_id")
	}
	if approved || sub != "" {
		t.Fatalf("must fail closed: sub=%q approved=%v", sub, approved)
	}
}

func TestPPIDSessionResolverSubNotRawUserID(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	r, _ := newTestResolver(t, userID, resolverTestSecret())

	sub, _, _, err := r.Resolve(context.Background(), resolverTestClient("rp-a", "rp-a.example.com"), "openid")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sub == userID {
		t.Fatal("subject (PPID) must never equal the raw user_id")
	}
}

// --- Additional error path tests ---

// errGrantStore returns fixed errors from FindGrant and CreateGrant.
type errGrantStore struct {
	findErr   error
	createErr error
}

func (s errGrantStore) FindGrant(_ context.Context, _, _ string) (Grant, bool, error) {
	if s.findErr != nil {
		return Grant{}, false, s.findErr
	}
	return Grant{}, false, nil
}

func (s errGrantStore) CreateGrant(_ context.Context, _ NewGrant) (Grant, error) {
	return Grant{}, s.createErr
}

func (s errGrantStore) RevokeGrant(_ context.Context, _ string) error {
	return nil
}

func (s errGrantStore) ListGrantsByUser(_ context.Context, _ string) ([]Grant, error) {
	return nil, nil
}

func TestPPIDSessionResolverFindGrantError(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	loader := NewInMemorySecretLoader()
	loader.Put(userID, UserSecret{Region: "us", Secret: resolverTestSecret()})

	r := NewPPIDSessionResolver(PPIDSessionResolverConfig{
		Auth:   NewFixedAuthSource(userID),
		Loader: loader,
		Grants: errGrantStore{findErr: errors.New("database connection lost")},
	})

	sub, _, approved, err := r.Resolve(context.Background(), resolverTestClient("rp-a", "rp-a.example.com"), "openid")
	if err == nil {
		t.Fatal("expected error on FindGrant failure")
	}
	if sub != "" || approved {
		t.Fatalf("expected empty non-approved subject, got sub=%q approved=%v", sub, approved)
	}
}

func TestPPIDSessionResolverCreateGrantError(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	loader := NewInMemorySecretLoader()
	loader.Put(userID, UserSecret{Region: "us", Secret: resolverTestSecret()})

	// findErr=nil so FindGrant returns (Grant{}, false, nil) — no existing grant.
	// createErr is set so CreateGrant fails.
	r := NewPPIDSessionResolver(PPIDSessionResolverConfig{
		Auth:   NewFixedAuthSource(userID),
		Loader: loader,
		Grants: errGrantStore{createErr: errors.New("constraint violation")},
	})

	sub, _, approved, err := r.Resolve(context.Background(), resolverTestClient("rp-a", "rp-a.example.com"), "openid")
	if err == nil {
		t.Fatal("expected error on CreateGrant failure")
	}
	if sub != "" || approved {
		t.Fatalf("expected empty non-approved subject, got sub=%q approved=%v", sub, approved)
	}
}

func TestPPIDSessionResolverEmptySecretError(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	loader := NewInMemorySecretLoader()
	// Put an empty secret — DerivePPID should fail.
	loader.Put(userID, UserSecret{Region: "us", Secret: []byte{}})

	r := NewPPIDSessionResolver(PPIDSessionResolverConfig{
		Auth:   NewFixedAuthSource(userID),
		Loader: loader,
		Grants: NewInMemoryGrantStore(),
	})

	sub, _, approved, err := r.Resolve(context.Background(), resolverTestClient("rp-a", "rp-a.example.com"), "openid")
	if err == nil {
		t.Fatal("expected error on empty secret")
	}
	if sub != "" || approved {
		t.Fatalf("expected empty non-approved subject, got sub=%q approved=%v", sub, approved)
	}
}

// errSecretLoader returns a fixed error from LoadUserSecret.
type errSecretLoader struct {
	err error
}

func (l errSecretLoader) LoadUserSecret(_ context.Context, _ string) (UserSecret, error) {
	return UserSecret{}, l.err
}

func TestPPIDSessionResolverSecretLoaderGenericError(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"

	// Test with a generic error (not ErrUserSecretNotFound).
	r := NewPPIDSessionResolver(PPIDSessionResolverConfig{
		Auth:   NewFixedAuthSource(userID),
		Loader: errSecretLoader{err: errors.New("decryption failed")},
		Grants: NewInMemoryGrantStore(),
	})

	sub, _, approved, err := r.Resolve(context.Background(), resolverTestClient("rp-a", "rp-a.example.com"), "openid")
	if err == nil {
		t.Fatal("expected error on secret loader failure")
	}
	// The raw user_id must NOT leak as the subject.
	if sub == userID {
		t.Fatalf("raw user_id leaked as subject: %q", sub)
	}
	if sub != "" || approved {
		t.Fatalf("expected empty non-approved subject, got sub=%q approved=%v", sub, approved)
	}
}
