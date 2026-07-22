package oidc_test

// Invariant anchor for asymmetric-only signing (registry: INV-SIGN-ASYM-ONLY).
// The real signer (ES256/EdDSA, key in the regional HSM) is not built yet; until
// it is, the placeholder issuer MUST emit obviously-unsigned scaffold tokens so
// nothing can mistake them for real — and there must be no symmetric/HS signer
// masquerading as production. See docs/DESIGN.md §3.3, §7.3, §A.8.

import (
	"context"
	"strings"
	"testing"

	"github.com/harbor-auth/harbor/internal/oidc"
)

//harbor:invariant INV-SIGN-ASYM-ONLY
func TestPlaceholderIssuerIsScaffoldNotReal(t *testing.T) {
	iss := oidc.NewPlaceholderIssuer()
	toks, err := iss.Issue(context.Background(), oidc.IssueParams{
		Issuer:   "https://eu.harbor.id",
		Subject:  "ppid-subject-123",
		ClientID: "demo-client",
		Scope:    "openid",
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	// Must be self-identifying as an unsigned scaffold.
	if !strings.Contains(toks.AccessToken, "UNSIGNED_PLACEHOLDER") {
		t.Errorf("access token is not a self-identifying scaffold: %q", toks.AccessToken)
	}
	if !strings.Contains(toks.IDToken, "UNSIGNED_PLACEHOLDER") {
		t.Errorf("id token is not a self-identifying scaffold: %q", toks.IDToken)
	}

	// Must NOT look like a real signed JWT (which starts with base64url of
	// `{"` == "eyJ" and has three dot-separated segments). If this ever trips,
	// a real signer has landed and this invariant test must be replaced with a
	// proper ES256/EdDSA + alg-allow-list assertion.
	for _, tok := range []string{toks.AccessToken, toks.IDToken} {
		if strings.HasPrefix(tok, "eyJ") && strings.Count(tok, ".") == 2 {
			t.Errorf("token looks like a real JWT but the HSM signer is not built — "+
				"replace this scaffold check with an ES256/EdDSA alg-allow-list test: %q", tok)
		}
	}
	if toks.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer", toks.TokenType)
	}
}
