package webauthn

import (
	"bytes"
	"testing"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// Compile-time proof that User satisfies the library's interface.
var _ gowebauthn.User = User{}

func TestNewUser_Accessors(t *testing.T) {
	id := []byte("user-123")
	creds := []gowebauthn.Credential{{ID: []byte("cred-1")}}
	u := NewUser(id, "alex@example.com", "Alex", creds)

	if !bytes.Equal(u.WebAuthnID(), id) {
		t.Fatalf("WebAuthnID = %q, want %q", u.WebAuthnID(), id)
	}
	if u.WebAuthnName() != "alex@example.com" {
		t.Fatalf("WebAuthnName = %q", u.WebAuthnName())
	}
	if u.WebAuthnDisplayName() != "Alex" {
		t.Fatalf("WebAuthnDisplayName = %q", u.WebAuthnDisplayName())
	}
	if got := u.WebAuthnCredentials(); len(got) != 1 || !bytes.Equal(got[0].ID, []byte("cred-1")) {
		t.Fatalf("WebAuthnCredentials = %+v", got)
	}
}
