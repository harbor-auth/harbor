package oidc

import (
	"net/http"
	"time"
)

// grantTypeAuthorizationCode is the code-exchange grant (docs/DESIGN.md §3.1).
const grantTypeAuthorizationCode = "authorization_code"

// grantTypeRefreshToken is the grant type for opaque, rotating, one-time-use
// refresh-token rotation (docs/DESIGN.md §3.5).
const grantTypeRefreshToken = "refresh_token"

// TokenRequest is the raw, untrusted form input to /token.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	CodeVerifier string
	RefreshToken string
}

// ValidateTokenParams checks the grant_type and required-parameter presence
// BEFORE the authorization code is consumed, so a malformed request never burns
// a valid one-time code. Pure (docs/DESIGN.md §1.7).
func ValidateTokenParams(req TokenRequest) *TokenError {
	switch req.GrantType {
	case grantTypeAuthorizationCode:
		if req.Code == "" || req.RedirectURI == "" || req.ClientID == "" || req.CodeVerifier == "" {
			return &TokenError{
				Code:        ErrCodeInvalidRequest,
				Description: "missing required parameter",
				Status:      http.StatusBadRequest,
			}
		}
	case grantTypeRefreshToken:
		if req.RefreshToken == "" || req.ClientID == "" {
			return &TokenError{
				Code:        ErrCodeInvalidRequest,
				Description: "missing required parameter",
				Status:      http.StatusBadRequest,
			}
		}
	default:
		return &TokenError{
			Code:        ErrCodeUnsupportedGrantType,
			Description: "only grant_type=authorization_code or refresh_token is supported",
			Status:      http.StatusBadRequest,
		}
	}
	return nil
}

// ValidateRefreshParams performs stateless validation of a refresh_token
// exchange against the looked-up session BEFORE the old token is rotated, so a
// malformed/mismatched request never burns a valid session. Every failure is
// invalid_grant (RFC 6749 §5.2) — we do not distinguish "wrong client" from
// "expired" in the wire error (docs/DESIGN.md §11.7).
func ValidateRefreshParams(req TokenRequest, session RefreshSession, now time.Time) *TokenError {
	if session.ClientID != req.ClientID {
		return invalidGrant("refresh token was not issued to this client")
	}
	if now.After(session.ExpiresAt) {
		return invalidGrant("refresh token has expired")
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
