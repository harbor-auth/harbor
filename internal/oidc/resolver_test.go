package oidc

import (
	"context"
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
