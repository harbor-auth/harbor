package oidc

import (
	"context"
	"testing"
)

// TestInMemorySecretLoader_PutClonesSecret verifies that Put clones the Secret
// []byte so a caller that reuses/mutates the slice after Put cannot corrupt the
// stored pairwise secret via the shared backing array (would produce wrong PPIDs
// silently with no error).
func TestInMemorySecretLoader_PutClonesSecret(t *testing.T) {
	l := NewInMemorySecretLoader()
	secret := []byte("original")
	l.Put("u1", UserSecret{Secret: secret})
	secret[0] = 'X' // mutate caller's slice after Put

	us, err := l.LoadUserSecret(context.Background(), "u1")
	if err != nil {
		t.Fatalf("LoadUserSecret: %v", err)
	}
	if us.Secret[0] == 'X' {
		t.Fatal("Put must clone Secret: caller mutation after Put corrupted the stored secret")
	}
}

// TestInMemorySecretLoader_LoadClonesSecret verifies that LoadUserSecret clones
// the Secret []byte so a caller that mutates the returned slice cannot corrupt
// the stored value seen by a subsequent load.
func TestInMemorySecretLoader_LoadClonesSecret(t *testing.T) {
	l := NewInMemorySecretLoader()
	l.Put("u1", UserSecret{Secret: []byte("original")})

	us, err := l.LoadUserSecret(context.Background(), "u1")
	if err != nil {
		t.Fatalf("LoadUserSecret: %v", err)
	}
	us.Secret[0] = 'X' // mutate returned slice

	us2, err := l.LoadUserSecret(context.Background(), "u1")
	if err != nil {
		t.Fatalf("LoadUserSecret (second): %v", err)
	}
	if us2.Secret[0] == 'X' {
		t.Fatal("LoadUserSecret must clone Secret: caller mutation of returned slice corrupted stored secret")
	}
}
