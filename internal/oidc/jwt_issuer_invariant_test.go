package oidc

import (
	"context"
	"encoding/json"
	"testing"
)

// TestJWTIssuerIsAsymmetric proves the real issuer mints ES256-signed JWTs
// whose signatures verify with the EC PUBLIC key — i.e. asymmetric signing,
// never a symmetric (HS*) MAC and never alg:none. This is the positive,
// real-token half of INV-SIGN-ASYM-ONLY (the placeholder-scaffold guard is the
// other half, retained while the scaffold issuer still exists).
//
//harbor:invariant INV-SIGN-ASYM-ONLY
func TestJWTIssuerIsAsymmetric(t *testing.T) {
	signer := newTestSigner(t)
	iss := NewJWTIssuer(JWTIssuerConfig{Signer: signer, Now: fixedNow})
	tokens, err := iss.Issue(context.Background(), testIssueParams())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	pub, err := signer.PublicJWK().ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey: %v", err)
	}

	for name, tok := range map[string]string{"id": tokens.IDToken, "access": tokens.AccessToken} {
		headerBytes, _, sig, err := parseCompactJWT(tok)
		if err != nil {
			t.Fatalf("%s parse: %v", name, err)
		}
		var hdr jwtHeader
		if err := json.Unmarshal(headerBytes, &hdr); err != nil {
			t.Fatalf("%s header unmarshal: %v", name, err)
		}
		if hdr.Alg != "ES256" {
			t.Fatalf("%s alg = %q, want ES256 (no symmetric/none)", name, hdr.Alg)
		}
		if len(sig) != 64 {
			t.Fatalf("%s sig len = %d, want 64 (raw ES256 R‖S)", name, len(sig))
		}
		// The signature must verify with the PUBLIC key — impossible for an HS*
		// MAC or an alg:none token.
		if !verifyES256(tok, pub) {
			t.Fatalf("%s token did not verify with EC public key", name)
		}
	}
}
