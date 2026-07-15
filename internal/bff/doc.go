// Package bff implements Harbor's Backend-For-Frontend session management
// (docs/DESIGN.md §9) — the secure browser session that binds the passkey
// ceremony to the OIDC flow. It holds the BFFSessionStore interface and
// implementations (in-memory for dev/test, Redis for production) so the
// ceremony handlers can read/write the authenticated user identity without
// trusting a client-supplied parameter.
//
// The BFF session is a short-lived, server-side record keyed by an opaque
// request_id. It carries the OIDC request context (state, client_id,
// redirect_uri) across the redirect to the login UI and back, and holds
// the authenticated user_id after the passkey ceremony completes.
package bff
