// Package webauthn implements Harbor's passkey (WebAuthn) registration and
// assertion ceremonies (docs/DESIGN.md §3.1, §7.1) — the primary, phishing-
// resistant authentication factor. It holds the relying-party configuration, the
// ceremony handlers, and the credential / ceremony-session stores behind
// interfaces, so the in-memory dev stores can be swapped for the sqlc-backed
// stores (db/queries) without touching the ceremony logic.
package webauthn
