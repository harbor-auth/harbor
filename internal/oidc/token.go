package oidc

import (
	"net/http"
	"time"
)

// grantTypeAuthorizationCode is the only grant Harbor supports at /token today
// (refresh_token is a documented next step; docs/DESIGN.md §3.1).
const grantTypeAuthorizationCode = "authorization_code"

// TokenRequest is the raw, untrusted form input to /token.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	CodeVerifier string
}

// ValidateTokenParams checks the grant_type and required-parameter presence
// BEFORE the authorization code is consumed, so a malformed request never burns
// a valid one-time code. Pure (docs/DESIGN.md §1.7).
func ValidateTokenParams(req TokenRequest) *TokenError {
	if req.GrantType != grantTypeAuthorizationCode {
		return &TokenError{
			Code:        ErrCodeUnsupportedGrantType,
			Description: "only grant_type=authorization_code is supported",
			Status:      http.StatusBadRequest,
		}
	}
	if req.Code == "" || req.RedirectURI == "" || req.ClientID == "" || req.CodeVerifier == "" {
		return &TokenError{
			Code:        ErrCodeInvalidRequest,
			Description: "missing required parameter",
			Status:      http.StatusBadRequest,
		}
	}
	return nil
}

// ValidateTokenExchange verifies a consumed authorization code against the
// presented request: client/redirect binding, expiry, and PKCE. Pure — the code
// is passed in, so there is no I/O to mock (docs/DESIGN.md §1.7, §11.7).
//
// Every failure here is `invalid_grant` (RFC 6749 §5.2): we deliberately do NOT
// distinguish "expired" from "mismatched PKCE" from "wrong client" in the error
// code, to avoid leaking which check failed.
func ValidateTokenExchange(req TokenRequest, code AuthCode, now time.Time) *TokenError {
	if code.ClientID != req.ClientID {
		return invalidGrant("authorization code was not issued to this client")
	}
	if code.RedirectURI != req.RedirectURI {
		return invalidGrant("redirect_uri does not match the authorization request")
	}
	if now.After(code.ExpiresAt) {
		return invalidGrant("authorization code has expired")
	}
	if err := VerifyChallenge(req.CodeVerifier, code.CodeChallenge); err != nil {
		return invalidGrant("PKCE verification failed")
	}
	return nil
}

// invalidGrant is a small constructor for the (400, invalid_grant) token error.
func invalidGrant(desc string) *TokenError {
	return &TokenError{
		Code:        ErrCodeInvalidGrant,
		Description: desc,
		Status:      http.StatusBadRequest,
	}
}
