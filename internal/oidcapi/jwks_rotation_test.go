package oidcapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/harbor/harbor/internal/crypto"
	"github.com/harbor/harbor/internal/gen/openapi"
)

// Integration test for the signing-key-rotation JWKS overlap invariant
// (docs/DESIGN.md §7.3, §3.5.4): during a rotation the old (draining) key and
// the new (active) key must BOTH appear in /jwks.json so in-flight tokens signed
// with the old key still verify while new tokens use the new key. Once the old
// key's overlap window elapses and it is retired, its kid must disappear from
// JWKS so retired-key tokens can no longer be verified.
//
// These tests exercise the real serving path end to end: MultiKeyProvider drives
// the live-signer set (overlap → Remove → retirement), those signers are wired
// into the oidcapi.Server, and the assertions read the actual GET /jwks.json
// HTTP response.

// newTestSigner generates a fresh dev ES256 signer for tests.
func newTestSigner(t *testing.T) crypto.Signer {
	t.Helper()
	s, err := crypto.NewLocalSigner()
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	return s
}

// fetchJWKSKids builds a Server serving the given live signers and returns the
// set of kids published at GET /jwks.json.
func fetchJWKSKids(t *testing.T, signers ...crypto.Signer) map[string]bool {
	t.Helper()
	srv := New(Config{Issuer: "https://eu.harbor.id", Signers: signers})

	req := httptest.NewRequest(http.MethodGet, "/jwks.json", nil)
	rec := httptest.NewRecorder()
	srv.GetJwks(rec, req)

	res := rec.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /jwks.json = %d, want 200", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var set openapi.JWKSet
	if err := json.NewDecoder(res.Body).Decode(&set); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	kids := make(map[string]bool, len(set.Keys))
	for _, k := range set.Keys {
		if kids[k.Kid] {
			t.Errorf("JWKS contains duplicate kid %q", k.Kid)
		}
		kids[k.Kid] = true
	}
	return kids
}

// TestJWKSServesMultipleKidsDuringOverlap verifies that during the rotation
// overlap window /jwks.json publishes BOTH the old and the new kid.
func TestJWKSServesMultipleKidsDuringOverlap(t *testing.T) {
	oldSigner := newTestSigner(t)
	newSigner := newTestSigner(t)
	if oldSigner.KeyID() == newSigner.KeyID() {
		t.Fatal("expected distinct kids for two freshly generated signers")
	}

	// Overlap: new key is active; old key is kept live so its public JWK stays
	// in JWKS while in-flight tokens drain (§7.3).
	provider, err := crypto.NewMultiKeyProvider(newSigner, oldSigner)
	if err != nil {
		t.Fatalf("NewMultiKeyProvider: %v", err)
	}

	kids := fetchJWKSKids(t, provider.AllSigners()...)
	if !kids[oldSigner.KeyID()] {
		t.Errorf("JWKS during overlap missing old (draining) kid %q", oldSigner.KeyID())
	}
	if !kids[newSigner.KeyID()] {
		t.Errorf("JWKS during overlap missing new (active) kid %q", newSigner.KeyID())
	}
	if len(kids) != 2 {
		t.Fatalf("JWKS during overlap published %d kids, want exactly 2", len(kids))
	}
}

// TestJWKSDropsOldKidAfterRetirement verifies that once the old key is retired
// (removed from the live set after its overlap window), its kid no longer
// appears in /jwks.json while the new active kid remains.
func TestJWKSDropsOldKidAfterRetirement(t *testing.T) {
	oldSigner := newTestSigner(t)
	newSigner := newTestSigner(t)

	provider, err := crypto.NewMultiKeyProvider(newSigner, oldSigner)
	if err != nil {
		t.Fatalf("NewMultiKeyProvider: %v", err)
	}
	// Retire the old key once its overlap window elapses.
	if err := provider.Remove(oldSigner.KeyID()); err != nil {
		t.Fatalf("Remove old signer: %v", err)
	}

	kids := fetchJWKSKids(t, provider.AllSigners()...)
	if kids[oldSigner.KeyID()] {
		t.Errorf("JWKS after retirement still publishes retired kid %q", oldSigner.KeyID())
	}
	if !kids[newSigner.KeyID()] {
		t.Errorf("JWKS after retirement missing active kid %q", newSigner.KeyID())
	}
	if len(kids) != 1 {
		t.Fatalf("JWKS after retirement published %d kids, want exactly 1", len(kids))
	}
}
