package oidc

// IntrospectRequest is the domain model for an RFC 7662 token introspection
// request. It is populated from the HTTP layer (oidcapi) after parsing the
// form-encoded body and authenticating the caller.
//
// Fields:
//   - Token: the access or refresh token to introspect (required).
//   - TokenTypeHint: optional hint ("access_token" or "refresh_token") to
//     optimize lookup order.
//   - ClientID: the authenticated caller's client_id (from Basic auth).
//   - IsAdmin: true when the caller authenticated with an admin Bearer token;
//     admin callers may introspect any token (cross-client allowed).
type IntrospectRequest struct {
	// Token is the access or refresh token to introspect. May be a JWT
	// (access token) or an opaque string (refresh token).
	Token string

	// TokenTypeHint is an optional hint about the token type. If omitted, the
	// introspection handler tries both access and refresh token lookups.
	// Valid values: "access_token", "refresh_token".
	TokenTypeHint string

	// ClientID is the authenticated caller's client_id. For Basic auth, this
	// is the username; for admin Bearer tokens, this may be empty (admin
	// callers are identified by IsAdmin=true instead).
	ClientID string

	// IsAdmin is true when the caller authenticated with an admin Bearer token.
	// Admin callers may introspect any token regardless of audience; non-admin
	// callers may only introspect tokens whose `aud` matches their ClientID
	// (cross-client isolation, RFC 7662 §2.1).
	IsAdmin bool
}

// IntrospectResponse is the domain model for an RFC 7662 token introspection
// response. The Active field is always present; additional claims are only
// populated when Active is true.
//
// For inactive tokens (expired, revoked, malformed, or cross-client queries),
// only Active=false is set — no other claims are leaked (enumeration
// resistance, docs/DESIGN.md §3.3, §3.5).
type IntrospectResponse struct {
	// Active is true if the token is valid, not expired, and not revoked.
	// False otherwise (expired, revoked, malformed, or cross-client query).
	Active bool

	// Sub is the pairwise subject identifier (PPID) for the token's user.
	// Only present when Active is true.
	Sub string

	// Scope is the space-delimited list of granted scopes.
	// Only present when Active is true.
	Scope string

	// ClientID is the client_id that the token was issued to.
	// Only present when Active is true.
	ClientID string

	// Exp is the token expiration time as Unix timestamp (seconds since epoch).
	// Only present when Active is true.
	Exp int64

	// Iat is the token issuance time as Unix timestamp (seconds since epoch).
	// Only present when Active is true.
	Iat int64

	// Iss is the issuer URL that minted the token.
	// Only present when Active is true.
	Iss string

	// Aud is the intended audience (typically the client_id).
	// Only present when Active is true.
	Aud string

	// Jti is the unique token identifier (JWT ID).
	// Only present when Active is true and the token is a JWT.
	Jti string

	// TokenType is the type of the token (e.g., "Bearer").
	// Only present when Active is true.
	TokenType string
}

// InactiveIntrospectResponse returns an IntrospectResponse with Active=false
// and no other claims. Use this for all negative introspection outcomes
// (expired, revoked, malformed, cross-client) to ensure enumeration resistance.
func InactiveIntrospectResponse() IntrospectResponse {
	return IntrospectResponse{Active: false}
}
