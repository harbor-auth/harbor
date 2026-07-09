// Package webauthn implements Harbor's passkey (FIDO2/WebAuthn) registration and
// assertion ceremonies (docs/DESIGN.md §3.1) on top of the certified
// go-webauthn library. Passkeys are Harbor's primary, phishing-resistant factor.
//
// The design follows §1.7's "pure core + thin I/O": the ceremony logic in
// service.go delegates to the library, while all persistence sits behind the
// Store and SessionStore interfaces (store.go). That keeps the flows testable
// without a database and lets the sqlc-backed credential/session queries plug in
// later without touching the ceremony code.
//
// The library package (github.com/go-webauthn/webauthn/webauthn) is imported as
// gowebauthn throughout to avoid clashing with this package's own name.
package webauthn

import (
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// User is a WebAuthn account: a stable user handle, human-facing labels, and the
// passkeys enrolled to it. It satisfies gowebauthn.User so it can be handed
// straight to the ceremony functions.
//
// It is a plain value built from storage rows (see Store), deliberately
// decoupled from the library's interface so the storage layer never depends on
// go-webauthn internals.
type User struct {
	id          []byte
	name        string
	displayName string
	credentials []gowebauthn.Credential
}

// NewUser builds a User. The id is the opaque WebAuthn user handle (docs/DESIGN.md
// §3.2 — never a globally-stable, correlatable identifier surfaced to an RP);
// name/displayName are for display only and are never used for auth decisions.
func NewUser(id []byte, name, displayName string, credentials []gowebauthn.Credential) User {
	return User{
		id:          id,
		name:        name,
		displayName: displayName,
		credentials: credentials,
	}
}

// WebAuthnID returns the user handle (opaque, ≤64 bytes).
func (u User) WebAuthnID() []byte { return u.id }

// WebAuthnName returns the human-palatable account name (display only).
func (u User) WebAuthnName() string { return u.name }

// WebAuthnDisplayName returns the human-palatable display name (display only).
func (u User) WebAuthnDisplayName() string { return u.displayName }

// WebAuthnCredentials returns the passkeys enrolled to this user.
func (u User) WebAuthnCredentials() []gowebauthn.Credential { return u.credentials }
