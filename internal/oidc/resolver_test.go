package oidc

import (
	"context"
	"errors"
	"testing"
)

// testSecret returns a deterministic 32-byte pairwise secret (all 1s) for tests.
func testSecret() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = 1
	}
	return s
}

// newTestResolver builds a PPIDSessionResolver with a fixed user, an in-memory
// secret loader seeded with that user's secret, and a fresh in-memory grant
// store. It returns the resolver plus the grant store so callers can assert on
// persisted grants.
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

func resolverTestClient(id, sector string) Client {
	return Client{ID: id, SectorID: sector, ScopesAllowed: []string{"openid", "profile"}}
}

//harbor:invariant INV-SESSION-PPID-STABLE
func TestPPIDSessionResolverStableSubject(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	r, grants := newTestResolver(t, userID, testSecret())
	client := resolverTestClient("rp-a", "rp-a.example.com")

	sub1, approved1, err := r.Resolve(context.Background(), client, "openid")
	if err != nil || !approved1 || sub1 == "" {
		t.Fatalf("first Resolve: sub=%q approved=%v err=%v", sub1, approved1, err)
	}

	sub2, approved2, err := r.Resolve(context.Background(), client, "openid")
	if err != nil || !approved2 {
		t.Fatalf("second Resolve: approved=%v err=%v", approved2, err)
	}
	if sub1 != sub2 {
		t.Fatalf("subject drifted: %q != %q", sub1, sub2)
	}

	list, err := grants.ListGrantsByUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListGrantsByUser: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected exactly 1 grant, got %d", len(list))
	}
}

//harbor:invariant INV-SESSION-PPID-UNLINKABLE
func TestPPIDSessionResolverUnlinkability(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	r, _ := newTestResolver(t, userID, testSecret())

	subA, _, err := r.Resolve(context.Background(), resolverTestClient("rp-a", "rp-a.example.com"), "openid")
	if err != nil {
		t.Fatalf("Resolve rp-a: %v", err)
	}
	subB, _, err := r.Resolve(context.Background(), resolverTestClient("rp-b", "rp-b.example.com"), "openid")
	if err != nil {
		t.Fatalf("Resolve rp-b: %v", err)
	}
	if subA == subB {
		t.Fatalf("different sectors produced the same sub: %q", subA)
	}
}

func TestPPIDSessionResolverGrantReuse(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	loader := NewInMemorySecretLoader()
	loader.Put(userID, UserSecret{Region: "us", Secret: testSecret()})
	grants := NewInMemoryGrantStore()
	r := NewPPIDSessionResolver(PPIDSessionResolverConfig{
		Auth:   NewFixedAuthSource(userID),
		Loader: loader,
		Grants: grants,
	})
	client := resolverTestClient("rp-a", "rp-a.example.com")

	sub1, _, err := r.Resolve(context.Background(), client, "openid")
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}

	// Change the secret — a re-derivation would now produce a DIFFERENT sub.
	// Because the grant is frozen, Resolve must still return the original sub.
	diff := make([]byte, 32)
	for i := range diff {
		diff[i] = 2
	}
	loader.Put(userID, UserSecret{Region: "us", Secret: diff})

	sub2, _, err := r.Resolve(context.Background(), client, "openid")
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if sub1 != sub2 {
		t.Fatalf("grant not reused: sub drifted %q -> %q after secret change", sub1, sub2)
	}
}

func TestPPIDSessionResolverFirstConsent(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	r, grants := newTestResolver(t, userID, testSecret())
	client := resolverTestClient("rp-a", "rp-a.example.com")

	sub, approved, err := r.Resolve(context.Background(), client, "openid profile")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !approved || sub == "" {
		t.Fatalf("expected approved with non-empty sub, got approved=%v sub=%q", approved, sub)
	}

	g, found, err := grants.FindGrant(context.Background(), userID, client.ID)
	if err != nil || !found {
		t.Fatalf("grant not recorded: found=%v err=%v", found, err)
	}
	if g.PairwiseSub != sub {
		t.Fatalf("grant PairwiseSub %q != resolved sub %q", g.PairwiseSub, sub)
	}
	if len(g.Scopes) != 2 || g.Scopes[0] != "openid" || g.Scopes[1] != "profile" {
		t.Fatalf("grant scopes = %v, want [openid profile]", g.Scopes)
	}
}

// errAuthSource returns a fixed error from AuthenticatedUserID.
type errAuthSource struct{ err error }

func (a errAuthSource) AuthenticatedUserID(context.Context) (string, error) {
	return "", a.err
}

//harbor:invariant INV-SESSION-PPID-NO-RAW-UID
func TestPPIDSessionResolverFailClosed(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	client := resolverTestClient("rp-a", "rp-a.example.com")

	t.Run("auth error", func(t *testing.T) {
		r := NewPPIDSessionResolver(PPIDSessionResolverConfig{
			Auth:   errAuthSource{err: errors.New("auth failed")},
			Loader: NewInMemorySecretLoader(),
			Grants: NewInMemoryGrantStore(),
		})
		sub, approved, err := r.Resolve(context.Background(), client, "openid")
		if err == nil {
			t.Fatal("expected error on auth failure")
		}
		if sub != "" || approved {
			t.Fatalf("expected empty non-approved subject, got sub=%q approved=%v", sub, approved)
		}
	})

	t.Run("secret load error", func(t *testing.T) {
		// Loader has no entry for userID → ErrUserSecretNotFound.
		r := NewPPIDSessionResolver(PPIDSessionResolverConfig{
			Auth:   NewFixedAuthSource(userID),
			Loader: NewInMemorySecretLoader(),
			Grants: NewInMemoryGrantStore(),
		})
		sub, approved, err := r.Resolve(context.Background(), client, "openid")
		if err == nil {
			t.Fatal("expected error on secret load failure")
		}
		// Critically: the raw user_id must NOT leak as the subject.
		if sub == userID {
			t.Fatalf("raw user_id leaked as subject: %q", sub)
		}
		if sub != "" || approved {
			t.Fatalf("expected empty non-approved subject, got sub=%q approved=%v", sub, approved)
		}
	})
}

func TestPPIDSessionResolverNoSectorID(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	r, _ := newTestResolver(t, userID, testSecret())

	sub, approved, err := r.Resolve(context.Background(), resolverTestClient("rp-a", ""), "openid")
	if err == nil {
		t.Fatal("expected error when client has no sector_id")
	}
	if sub != "" || approved {
		t.Fatalf("expected empty non-approved subject, got sub=%q approved=%v", sub, approved)
	}
}

func TestPPIDSessionResolverSubIsNotUserID(t *testing.T) {
	const userID = "00000000-0000-0000-0000-000000000001"
	r, _ := newTestResolver(t, userID, testSecret())

	sub, _, err := r.Resolve(context.Background(), resolverTestClient("rp-a", "rp-a.example.com"), "openid")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sub == userID {
		t.Fatalf("sub must be a PPID, not the raw user_id (%q)", userID)
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
	loader.Put(userID, UserSecret{Region: "us", Secret: testSecret()})

	r := NewPPIDSessionResolver(PPIDSessionResolverConfig{
		Auth:   NewFixedAuthSource(userID),
		Loader: loader,
		Grants: errGrantStore{findErr: errors.New("database connection lost")},
	})

	sub, approved, err := r.Resolve(context.Background(), resolverTestClient("rp-a", "rp-a.example.com"), "openid")
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
	loader.Put(userID, UserSecret{Region: "us", Secret: testSecret()})

	// findErr=nil so FindGrant returns (Grant{}, false, nil) — no existing grant.
	// createErr is set so CreateGrant fails.
	r := NewPPIDSessionResolver(PPIDSessionResolverConfig{
		Auth:   NewFixedAuthSource(userID),
		Loader: loader,
		Grants: errGrantStore{createErr: errors.New("constraint violation")},
	})

	sub, approved, err := r.Resolve(context.Background(), resolverTestClient("rp-a", "rp-a.example.com"), "openid")
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

	sub, approved, err := r.Resolve(context.Background(), resolverTestClient("rp-a", "rp-a.example.com"), "openid")
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

	sub, approved, err := r.Resolve(context.Background(), resolverTestClient("rp-a", "rp-a.example.com"), "openid")
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
