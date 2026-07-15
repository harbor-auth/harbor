package crypto

import (
	"errors"
	"testing"
)

// mustSigner creates a fresh LocalSigner for tests, failing the test on error.
func mustSigner(t *testing.T) *LocalSigner {
	t.Helper()
	s, err := NewLocalSigner()
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	return s
}

func TestMultiKeyProviderImplementsInterface(t *testing.T) {
	var _ SigningKeyProvider = (*MultiKeyProvider)(nil)
}

func TestNewMultiKeyProviderNilActive(t *testing.T) {
	if _, err := NewMultiKeyProvider(nil); err == nil {
		t.Fatal("expected error for nil active signer")
	}
}

func TestNewMultiKeyProviderNilPending(t *testing.T) {
	active := mustSigner(t)
	if _, err := NewMultiKeyProvider(active, nil); err == nil {
		t.Fatal("expected error for nil pending signer")
	}
}

func TestNewMultiKeyProviderDuplicateKid(t *testing.T) {
	active := mustSigner(t)
	// Passing the same signer twice yields a duplicate kid.
	_, err := NewMultiKeyProvider(active, active)
	if !errors.Is(err, ErrDuplicateKid) {
		t.Fatalf("expected ErrDuplicateKid, got %v", err)
	}
}

func TestMultiKeyProviderActiveSigner(t *testing.T) {
	active := mustSigner(t)
	p, err := NewMultiKeyProvider(active)
	if err != nil {
		t.Fatalf("NewMultiKeyProvider: %v", err)
	}
	if p.ActiveSigner().KeyID() != active.KeyID() {
		t.Errorf("ActiveSigner kid: got %q, want %q", p.ActiveSigner().KeyID(), active.KeyID())
	}
}

func TestMultiKeyProviderAllSigners(t *testing.T) {
	active := mustSigner(t)
	pending := mustSigner(t)
	p, err := NewMultiKeyProvider(active, pending)
	if err != nil {
		t.Fatalf("NewMultiKeyProvider: %v", err)
	}
	all := p.AllSigners()
	if len(all) != 2 {
		t.Fatalf("AllSigners: got %d signers, want 2", len(all))
	}
	// Active is always first (insertion order).
	if all[0].KeyID() != active.KeyID() {
		t.Errorf("AllSigners[0] kid: got %q, want active %q", all[0].KeyID(), active.KeyID())
	}
	if all[1].KeyID() != pending.KeyID() {
		t.Errorf("AllSigners[1] kid: got %q, want pending %q", all[1].KeyID(), pending.KeyID())
	}
}

func TestMultiKeyProviderSignerByKid(t *testing.T) {
	active := mustSigner(t)
	pending := mustSigner(t)
	p, err := NewMultiKeyProvider(active, pending)
	if err != nil {
		t.Fatalf("NewMultiKeyProvider: %v", err)
	}

	got, ok := p.SignerByKid(pending.KeyID())
	if !ok {
		t.Fatal("SignerByKid: expected pending signer to be found")
	}
	if got.KeyID() != pending.KeyID() {
		t.Errorf("SignerByKid: got kid %q, want %q", got.KeyID(), pending.KeyID())
	}

	if _, ok := p.SignerByKid("no-such-kid"); ok {
		t.Error("SignerByKid: expected not found for unknown kid")
	}
}

func TestMultiKeyProviderAdd(t *testing.T) {
	active := mustSigner(t)
	p, err := NewMultiKeyProvider(active)
	if err != nil {
		t.Fatalf("NewMultiKeyProvider: %v", err)
	}

	pending := mustSigner(t)
	if err := p.Add(pending); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if len(p.AllSigners()) != 2 {
		t.Fatalf("after Add: got %d signers, want 2", len(p.AllSigners()))
	}

	// Adding the same kid again must fail.
	if err := p.Add(pending); !errors.Is(err, ErrDuplicateKid) {
		t.Fatalf("Add duplicate: expected ErrDuplicateKid, got %v", err)
	}

	// Adding nil must fail.
	if err := p.Add(nil); err == nil {
		t.Error("Add(nil): expected error")
	}

	// Add does not change the active signer.
	if p.ActiveSigner().KeyID() != active.KeyID() {
		t.Error("Add must not change the active signer")
	}
}

func TestMultiKeyProviderSetActive(t *testing.T) {
	active := mustSigner(t)
	pending := mustSigner(t)
	p, err := NewMultiKeyProvider(active, pending)
	if err != nil {
		t.Fatalf("NewMultiKeyProvider: %v", err)
	}

	if err := p.SetActive(pending.KeyID()); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	if p.ActiveSigner().KeyID() != pending.KeyID() {
		t.Errorf("after SetActive: active kid %q, want %q", p.ActiveSigner().KeyID(), pending.KeyID())
	}

	// The old active signer stays live (overlap window).
	if _, ok := p.SignerByKid(active.KeyID()); !ok {
		t.Error("old active signer should remain live after SetActive")
	}

	// Unknown kid must fail.
	if err := p.SetActive("no-such-kid"); err == nil {
		t.Error("SetActive unknown kid: expected error")
	}
}

func TestMultiKeyProviderRemove(t *testing.T) {
	active := mustSigner(t)
	pending := mustSigner(t)
	p, err := NewMultiKeyProvider(active, pending)
	if err != nil {
		t.Fatalf("NewMultiKeyProvider: %v", err)
	}

	// Cannot remove the active signer.
	if err := p.Remove(active.KeyID()); err == nil {
		t.Error("Remove active: expected error")
	}

	// Removing an unknown kid fails.
	if err := p.Remove("no-such-kid"); err == nil {
		t.Error("Remove unknown kid: expected error")
	}

	// Removing a live non-active signer succeeds.
	if err := p.Remove(pending.KeyID()); err != nil {
		t.Fatalf("Remove pending: %v", err)
	}
	if len(p.AllSigners()) != 1 {
		t.Fatalf("after Remove: got %d signers, want 1", len(p.AllSigners()))
	}
	if _, ok := p.SignerByKid(pending.KeyID()); ok {
		t.Error("removed signer should no longer be live")
	}
}
