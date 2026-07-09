package oidc

import "strings"

// ScopeOpenID is the scope that makes an OAuth request an OIDC request; it MUST
// be present at /authorize (docs/DESIGN.md §11.2).
const ScopeOpenID = "openid"

// responseTypeCode is the only response_type Harbor supports (OAuth 2.1 — no
// implicit flow, docs/DESIGN.md §3.1).
const responseTypeCode = "code"

// AuthorizeRequest is the raw, untrusted input to /authorize (each field maps to
// a query parameter). It is a plain value so ValidateAuthorize stays a pure
// function.
type AuthorizeRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// ValidatedAuthorize is a request that has passed every /authorize check. Its
// existence proves the redirect_uri was matched exactly and PKCE is present, so
// the caller may safely proceed to login/consent and code issuance.
type ValidatedAuthorize struct {
	Client              Client
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// ValidateAuthorize validates an /authorize request against the resolved client
// (nil = unknown client_id). It is PURE: no I/O, so every branch is unit-tested
// directly (docs/DESIGN.md §1.7, §11.7).
//
// The ORDER of checks is the open-redirect defense and must not be reordered:
//
//  1. Unknown client_id, or a redirect_uri that is not an EXACT registered
//     match, is surfaced via ChannelErrorPage — we must NOT redirect to an
//     unproven URI (docs/DESIGN.md §11.7 "channel a exception").
//  2. Only AFTER the redirect target is proven trusted do the remaining checks
//     run, and their failures are ChannelRedirect (safe to send back to the RP).
func ValidateAuthorize(req AuthorizeRequest, client *Client) (*ValidatedAuthorize, *AuthorizeError) {
	// (1) Prove the redirect target BEFORE anything else. These two failures are
	// the only ones that must never redirect.
	if client == nil {
		return nil, &AuthorizeError{
			Code:        ErrCodeUnauthorizedClient,
			Description: "unknown client",
			Channel:     ChannelErrorPage,
		}
	}
	if req.RedirectURI == "" || !client.HasRedirectURI(req.RedirectURI) {
		return nil, &AuthorizeError{
			Code:        ErrCodeInvalidRequest,
			Description: "redirect_uri is missing or does not match a registered URI",
			Channel:     ChannelErrorPage,
		}
	}

	// (2) Redirect target is trusted — remaining errors go back via redirect.
	if req.ResponseType != responseTypeCode {
		return nil, redirectErr(ErrCodeUnsupportedResponseType, "only response_type=code is supported")
	}

	if err := validateScope(req.Scope, *client); err != nil {
		return nil, err
	}

	// PKCE is mandatory; S256 only — `plain`/empty are rejected (§3.1, §11.7).
	if err := ValidateChallengeMethod(req.CodeChallengeMethod); err != nil {
		return nil, redirectErr(ErrCodeInvalidRequest, "code_challenge_method must be S256")
	}
	if req.CodeChallenge == "" {
		return nil, redirectErr(ErrCodeInvalidRequest, "code_challenge is required (PKCE)")
	}

	// `state` is the RP's CSRF binding; require it so it can be echoed back.
	if req.State == "" {
		return nil, redirectErr(ErrCodeInvalidRequest, "state is required")
	}

	return &ValidatedAuthorize{
		Client:              *client,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}, nil
}

// validateScope enforces that `openid` is present and every requested scope is
// permitted for the client (docs/DESIGN.md §11.7).
func validateScope(scope string, client Client) *AuthorizeError {
	requested := strings.Fields(scope)
	var hasOpenID bool
	for _, s := range requested {
		if s == ScopeOpenID {
			hasOpenID = true
		}
		if !scopeAllowed(s, client.ScopesAllowed) {
			return redirectErr(ErrCodeInvalidScope, "requested scope is unknown or not permitted")
		}
	}
	if !hasOpenID {
		return redirectErr(ErrCodeInvalidScope, "the openid scope is required")
	}
	return nil
}

// scopeAllowed reports whether s is in allowed. An empty allow-list permits
// nothing (deny-by-default).
func scopeAllowed(s string, allowed []string) bool {
	for _, a := range allowed {
		if a == s {
			return true
		}
	}
	return false
}

// redirectErr is a small constructor for redirect-channel authorize errors.
func redirectErr(code, desc string) *AuthorizeError {
	return &AuthorizeError{Code: code, Description: desc, Channel: ChannelRedirect}
}
