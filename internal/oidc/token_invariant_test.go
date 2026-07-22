package oidc_test

// Invariant anchors for the /token exchange non-negotiables (registry:
// INV-INVALID-GRANT-GENERIC, INV-REDIRECT-EXACT, INV-CODE-SINGLE-USE). All three
// are proven against the pure ValidateTokenExchange (docs/DESIGN.md §11.7): it
// receives an already-looked-up AuthCode, so there is no I/O to mock. The
// store-level "consume exactly once" behavior is additionally exercised by the
// service tests; here we lock the pure-layer contract.

import (
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/oidc"
)

// liveCodeAndRequest returns a matching (AuthCode, TokenRequest) pair that would
// exchange successfully, using the RFC 7636 PKCE pair.
func liveCodeAndRequest(now time.Time) (oidc.AuthCode, oidc.TokenRequest) {
	code := oidc.AuthCode{
		ClientID:      "demo-client",
		RedirectURI:   "https://rp.example/callback",
		ExpiresAt:     now.Add(60 * time.Second),
		CodeChallenge: rfcChallenge,
	}
	req := oidc.TokenRequest{
		GrantType:    "authorization_code",
		Code:         "the-code",
		RedirectURI:  "https://rp.example/callback",
		ClientID:     "demo-client",
		CodeVerifier: rfcVerifier,
	}
	return code, req
}

//harbor:invariant INV-INVALID-GRANT-GENERIC
func TestTokenExchangeFailuresAllInvalidGrant(t *testing.T) {
	now := time.Now()

	// Baseline: the live pair must NOT be rejected by the exchange checks.
	if code, req := liveCodeAndRequest(now); oidc.ValidateTokenExchange(req, code, now) != nil {
		t.Fatalf("baseline live exchange unexpectedly rejected")
	}

	cases := []struct {
		name   string
		mutate func(*oidc.AuthCode, *oidc.TokenRequest, time.Time) time.Time
	}{
		{"wrong client", func(_ *oidc.AuthCode, r *oidc.TokenRequest, n time.Time) time.Time {
			r.ClientID = "attacker-client"
			return n
		}},
		{"wrong redirect", func(_ *oidc.AuthCode, r *oidc.TokenRequest, n time.Time) time.Time {
			r.RedirectURI = "https://rp.example/other"
			return n
		}},
		{"expired code", func(c *oidc.AuthCode, _ *oidc.TokenRequest, n time.Time) time.Time {
			c.ExpiresAt = n.Add(-1 * time.Second)
			return n
		}},
		{"bad PKCE", func(_ *oidc.AuthCode, r *oidc.TokenRequest, n time.Time) time.Time {
			r.CodeVerifier = "wrong-verifier-but-valid-length-000000000000"
			return n
		}},
	}

	for _, tc := range cases {
		code, req := liveCodeAndRequest(now)
		at := tc.mutate(&code, &req, now)
		te := oidc.ValidateTokenExchange(req, code, at)
		if te == nil {
			t.Errorf("%s: expected rejection, got success", tc.name)
			continue
		}
		// The invariant: EVERY failure collapses to the same generic code.
		if te.Code != oidc.ErrCodeInvalidGrant {
			t.Errorf("%s: Code = %v, want ErrCodeInvalidGrant (must not leak which check failed)", tc.name, te.Code)
		}
	}
}

//harbor:invariant INV-REDIRECT-EXACT
func TestExactRedirectURIMatch(t *testing.T) {
	now := time.Now()

	// Near-miss redirects that a lenient (prefix/substring/trailing-slash)
	// matcher might wrongly accept must all be rejected as invalid_grant.
	nearMisses := []string{
		"https://rp.example/callback/",     // trailing slash
		"https://rp.example/callback?x=1",  // extra query
		"https://rp.example/callback#frag", // fragment
		"https://rp.example/callbackEVIL",  // prefix extension
		"https://rp.example",               // shorter
		"http://rp.example/callback",       // scheme downgrade
	}
	for _, rm := range nearMisses {
		code, req := liveCodeAndRequest(now)
		req.RedirectURI = rm
		if te := oidc.ValidateTokenExchange(req, code, now); te == nil || te.Code != oidc.ErrCodeInvalidGrant {
			t.Errorf("redirect_uri %q was not rejected exactly (te=%v) — must be an EXACT match", rm, te)
		}
	}

	// The exact match must pass the redirect check.
	if code, req := liveCodeAndRequest(now); oidc.ValidateTokenExchange(req, code, now) != nil {
		t.Errorf("exact redirect_uri match was rejected")
	}
}

//harbor:invariant INV-CODE-SINGLE-USE
func TestAuthCodeSingleUse(t *testing.T) {
	now := time.Now()

	// A code that is no longer live (past its short one-time TTL) must be
	// rejected as invalid_grant — the pure-layer half of "single-use": a code is
	// valid for exactly one live exchange window, never afterward. Consume-once
	// at the store layer is covered by the service tests.
	code, req := liveCodeAndRequest(now)
	code.ExpiresAt = now.Add(-1 * time.Millisecond)
	te := oidc.ValidateTokenExchange(req, code, now)
	if te == nil || te.Code != oidc.ErrCodeInvalidGrant {
		t.Fatalf("non-live (expired) code was accepted (te=%v), want invalid_grant", te)
	}
}
