// Package oidc holds Harbor's OAuth 2.1 / OpenID Connect Authorization Code
// flow logic: PKCE verification, /authorize request validation, and /token code
// exchange. Following docs/DESIGN.md §1.7, the security-critical logic here is a
// PURE core (no net/http, no database) so it is exhaustively unit-testable
// without mocks; the thin I/O layer lives in internal/oidcapi and the stores in
// this package's *interfaces* (store.go), with in-memory implementations for now.
package oidc

// OAuth 2.0 / OIDC error codes (RFC 6749 §4.1.2.1 and §5.2, OIDC Core). These
// are the exact wire strings Harbor emits — negative tests assert them verbatim
// (docs/DESIGN.md §11.7).
const (
	ErrCodeInvalidRequest          = "invalid_request"
	ErrCodeUnauthorizedClient      = "unauthorized_client"
	ErrCodeAccessDenied            = "access_denied"
	ErrCodeUnsupportedResponseType = "unsupported_response_type"
	ErrCodeInvalidScope            = "invalid_scope"
	ErrCodeServerError             = "server_error"
	ErrCodeTemporarilyUnavailable  = "temporarily_unavailable"
	ErrCodeInvalidGrant            = "invalid_grant"
	ErrCodeInvalidClient           = "invalid_client"
	ErrCodeUnsupportedGrantType    = "unsupported_grant_type"
)

// ErrorChannel selects HOW an /authorize error is surfaced (docs/DESIGN.md
// §11.7). Choosing the channel correctly is the open-redirect defense: an error
// may only be redirected to a redirect_uri we have PROVEN is registered.
type ErrorChannel int

const (
	// ChannelRedirect: 302 back to the RP's *validated* redirect_uri with
	// error/error_description/state. Safe only because the target was verified.
	ChannelRedirect ErrorChannel = iota
	// ChannelErrorPage: render a browser error page and NEVER set a Location
	// header. Used when the redirect target is not proven trusted (unknown
	// client_id or non-matching redirect_uri) — redirecting there would be an
	// open-redirect / token-exfiltration vector.
	ChannelErrorPage
)

// AuthorizeError is an /authorize failure together with the channel that MUST
// be used to surface it.
type AuthorizeError struct {
	Code        string
	Description string
	Channel     ErrorChannel
}

func (e *AuthorizeError) Error() string { return e.Code + ": " + e.Description }

// TokenError is a /token failure. Status is the HTTP status to emit (400 for
// most OAuth errors, 401 for client-auth failures; RFC 6749 §5.2).
type TokenError struct {
	Code        string
	Description string
	Status      int
}

func (e *TokenError) Error() string { return e.Code + ": " + e.Description }
