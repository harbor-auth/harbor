package oidc

import (
	"context"
	"time"
)

// Client is an RP registration — the subset of relying_parties (docs/DESIGN.md
// §10) the flow needs. It is passed BY VALUE into the pure validators so they
// stay free of I/O.
type Client struct {
	ID                      string
	SectorID                string // groups redirect URIs for PPID derivation (DESIGN §3.2)
	RedirectURIs            []string
	LogoutURIs              []string // registered post_logout_redirect_uri values (OIDC RP-Initiated Logout)
	ScopesAllowed           []string
	TokenEndpointAuthMethod string
	SecretHash              []byte
}

// HasRedirectURI reports whether uri EXACTLY matches a registered redirect URI
// (docs/DESIGN.md §11.7, §7.4 — exact string match, never prefix/substring:
// loose matching is a classic open-redirect hole).
func (c Client) HasRedirectURI(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// HasLogoutURI reports whether uri EXACTLY matches a registered logout URI
// (post_logout_redirect_uri for RP-Initiated Logout). Like HasRedirectURI, this
// uses exact string matching to prevent open-redirect vulnerabilities.
func (c Client) HasLogoutURI(uri string) bool {
	for _, u := range c.LogoutURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// ClientRegistry looks up RP registrations by client_id. Production wiring uses
// the SQL-backed registry in internal/clients.
type ClientRegistry interface {
	Lookup(ctx context.Context, clientID string) (Client, bool)
}

// AuthCode is the state captured at /authorize and consumed at /token. It binds
// the PKCE challenge, the resolved subject (PPID), and the exact client/redirect
// so the token exchange can re-verify them.
type AuthCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	Scope               string
	Subject             string // PPID the RP will see (docs/DESIGN.md §3.2)
	UserID              string // internal user UUID; needed to bind a refresh session (§3.5)
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	AuthTime            time.Time // when the user authenticated (OIDC Core §2)
	ACR                 string    // authentication context class reference (OIDC Core §2)
	AMR                 []string  // authentication methods references (OIDC Core §2)
}

// ConsumeStatus is the outcome of AuthCodeStore.Consume.
type ConsumeStatus int

const (
	// ConsumeNotFound: the code was never issued (or was pruned).
	ConsumeNotFound ConsumeStatus = iota
	// ConsumeFirstUse: the code is valid and now marked consumed.
	ConsumeFirstUse
	// ConsumeReused: the code was ALREADY consumed — a theft signal. The caller
	// must reject with invalid_grant AND revoke tokens minted from it
	// (docs/DESIGN.md §11.7, §3.5).
	ConsumeReused
)

// ConsumeResult pairs the status with the stored code (populated for both
// FirstUse and Reused so the caller can act on the theft signal).
type ConsumeResult struct {
	Status ConsumeStatus
	Code   AuthCode
}

// AuthCodeStore issues and consumes single-use authorization codes. Consume is
// TOMBSTONING — it marks a code consumed rather than deleting it — so a second
// presentation is reported as ConsumeReused (not ConsumeNotFound), which is what
// lets Harbor detect code theft. Expiry is enforced by the caller against
// AuthCode.ExpiresAt, keeping this store deliberately dumb.
//
// Peek reads the stored code WITHOUT mutating it, so the caller can validate
// binding + PKCE against a stolen code before burning the legitimate one
// (docs/DESIGN.md §11.7 — a failed exchange must never consume a valid code).
type AuthCodeStore interface {
	Save(ctx context.Context, code AuthCode) error
	// Peek returns the stored code (found=true) and whether it has already been
	// consumed, without changing its state.
	Peek(ctx context.Context, code string) (stored AuthCode, found bool, consumed bool, err error)
	Consume(ctx context.Context, code string) (ConsumeResult, error)
}
