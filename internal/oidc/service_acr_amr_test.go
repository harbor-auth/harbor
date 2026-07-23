package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/crypto"
)

// acrAMRFlowServer builds a minimal Service wired for BFF-path ACR/AMR tests.
func acrAMRFlowServer(t *testing.T) (*Service, *InMemoryAuthCodeStore) {
	t.Helper()
	clients := NewInMemoryClientRegistry()
	clients.Put(Client{
		ID:            "acr-test-client",
		SectorID:      "example.com",
		RedirectURIs:  []string{"https://example.com/callback"},
		ScopesAllowed: []string{"openid"},
	})
	codes := NewInMemoryAuthCodeStore()
	signer, err := crypto.NewLocalSigner()
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	svc := NewService(ServiceConfig{
		Issuer:   "https://eu.harbor.id",
		Clients:  clients,
		Codes:    codes,
		Tokens:   NewJWTIssuer(JWTIssuerConfig{Signer: signer}),
		Sessions: NewStubSessionResolver("test-ppid"),
	})
	return svc, codes
}

// acrAMRAuthorizeWithUser runs AuthorizeWithUser with the given AuthMethod and
// returns the persisted AuthCode (which carries ACR/AMR into IssueParams).
func acrAMRAuthorizeWithUser(t *testing.T, svc *Service, method AuthMethod) AuthCode {
	t.Helper()
	ctx := context.Background()
	result, aerr := svc.AuthorizeWithUser(ctx, AuthorizeWithUserRequest{
		ClientID:            "acr-test-client",
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		State:               "s1",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		UserID:              "user-1",
		AuthMethod:          method,
	})
	if aerr != nil {
		t.Fatalf("AuthorizeWithUser(%q) returned error: %v", method, aerr)
	}
	// Peek the stored code to inspect ACR/AMR before token issuance.
	stored, found, consumed, err := svc.codes.Peek(ctx, result.Code)
	if err != nil || !found || consumed {
		t.Fatalf("Peek(%q): err=%v found=%v consumed=%v", result.Code, err, found, consumed)
	}
	return stored
}

// decodeIDTokenClaims decodes the payload of a compact JWT without verifying the
// signature — sufficient for inspecting claims in unit tests.
func decodeIDTokenClaims(t *testing.T, idToken string) map[string]any {
	t.Helper()
	parts := splitJWT(t, idToken)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal JWT claims: %v", err)
	}
	return claims
}

func splitJWT(t *testing.T, tok string) []string {
	t.Helper()
	var parts []string
	start := 0
	for i, c := range tok {
		if c == '.' {
			parts = append(parts, tok[start:i])
			start = i + 1
		}
	}
	parts = append(parts, tok[start:])
	if len(parts) != 3 {
		t.Fatalf("invalid JWT: expected 3 parts, got %d", len(parts))
	}
	return parts
}

// TestAuthorizeWithUser_WebAuthn_ACR_AMR verifies that AuthMethodWebAuthn produces
// the correct acr/amr claims in the issued token.
func TestAuthorizeWithUser_WebAuthn_ACR_AMR(t *testing.T) {
	svc, _ := acrAMRFlowServer(t)
	code := acrAMRAuthorizeWithUser(t, svc, AuthMethodWebAuthn)

	if code.ACR != "urn:harbor:ac:webauthn" {
		t.Errorf("ACR = %q, want %q", code.ACR, "urn:harbor:ac:webauthn")
	}
	if len(code.AMR) != 2 || code.AMR[0] != "hwk" || code.AMR[1] != "user" {
		t.Errorf("AMR = %v, want [hwk user]", code.AMR)
	}
}

// TestAuthorizeWithUser_TOTP_ACR_AMR verifies that AuthMethodTOTP produces the
// correct acr/amr claims (webauthn+totp with hwk+otp+user).
func TestAuthorizeWithUser_TOTP_ACR_AMR(t *testing.T) {
	svc, _ := acrAMRFlowServer(t)
	code := acrAMRAuthorizeWithUser(t, svc, AuthMethodTOTP)

	if code.ACR != "urn:harbor:ac:webauthn+totp" {
		t.Errorf("ACR = %q, want %q", code.ACR, "urn:harbor:ac:webauthn+totp")
	}
	if len(code.AMR) != 3 || code.AMR[0] != "hwk" || code.AMR[1] != "otp" || code.AMR[2] != "user" {
		t.Errorf("AMR = %v, want [hwk otp user]", code.AMR)
	}
}

// TestAuthorizeWithUser_RecoveryCode_ACR_AMR verifies that AuthMethodRecoveryCode
// produces the correct acr/amr claims.
func TestAuthorizeWithUser_RecoveryCode_ACR_AMR(t *testing.T) {
	svc, _ := acrAMRFlowServer(t)
	code := acrAMRAuthorizeWithUser(t, svc, AuthMethodRecoveryCode)

	if code.ACR != "urn:harbor:ac:recovery" {
		t.Errorf("ACR = %q, want %q", code.ACR, "urn:harbor:ac:recovery")
	}
	if len(code.AMR) != 1 || code.AMR[0] != "rc" {
		t.Errorf("AMR = %v, want [rc]", code.AMR)
	}
}

// TestAuthorizeWithUser_UnknownMethod_FailClosed verifies that an unknown or
// empty AuthMethod emits no ACR/AMR claims (fail-closed invariant, OIDC Core §2).
func TestAuthorizeWithUser_UnknownMethod_FailClosed(t *testing.T) {
	svc, _ := acrAMRFlowServer(t)

	for _, method := range []AuthMethod{"", "unknown-method", AuthMethod("invalid")} {
		code := acrAMRAuthorizeWithUser(t, svc, method)
		if code.ACR != "" {
			t.Errorf("method=%q: ACR = %q, want empty (fail-closed)", method, code.ACR)
		}
		if len(code.AMR) != 0 {
			t.Errorf("method=%q: AMR = %v, want nil/empty (fail-closed)", method, code.AMR)
		}
	}
}

// TestLegacyAuthorize_FailClosed verifies the legacy Authorize() path emits
// no ACR/AMR claims (no hardcoded strings; omit rather than lie).
func TestLegacyAuthorize_FailClosed(t *testing.T) {
	svc, codes := acrAMRFlowServer(t)
	ctx := context.Background()

	result, aerr := svc.Authorize(ctx, AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "acr-test-client",
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		State:               "s1",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	})
	if aerr != nil {
		t.Fatalf("Authorize failed: %v", aerr)
	}

	stored, found, consumed, err := codes.Peek(ctx, result.Code)
	if err != nil || !found || consumed {
		t.Fatalf("Peek: err=%v found=%v consumed=%v", err, found, consumed)
	}
	if stored.ACR != "" {
		t.Errorf("legacy Authorize: ACR = %q, want empty (fail-closed: no hardcoded strings)", stored.ACR)
	}
	if len(stored.AMR) != 0 {
		t.Errorf("legacy Authorize: AMR = %v, want nil/empty (fail-closed)", stored.AMR)
	}
}

// TestAuthorizeWithUser_WebAuthn_IDTokenClaims_E2E verifies the full pipeline:
// AuthMethodWebAuthn flows from AuthorizeWithUserRequest → AuthCode → Token →
// issued id_token with correct acr/amr JWT claims.
func TestAuthorizeWithUser_WebAuthn_IDTokenClaims_E2E(t *testing.T) {
	svc, _ := acrAMRFlowServer(t)
	ctx := context.Background()

	// Issue a code with WebAuthn auth method.
	result, aerr := svc.AuthorizeWithUser(ctx, AuthorizeWithUserRequest{
		ClientID:            "acr-test-client",
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		State:               "s1",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		UserID:              "user-1",
		AuthMethod:          AuthMethodWebAuthn,
	})
	if aerr != nil {
		t.Fatalf("AuthorizeWithUser: %v", aerr)
	}

	// Exchange for tokens via the real Token() path.
	tokens, terr := svc.Token(ctx, TokenRequest{
		GrantType:    "authorization_code",
		Code:         result.Code,
		RedirectURI:  "https://example.com/callback",
		ClientID:     "acr-test-client",
		CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	})
	if terr != nil {
		t.Fatalf("Token: %v", terr)
	}

	// Decode the id_token and assert ACR/AMR claims are correct.
	claims := decodeIDTokenClaims(t, tokens.IDToken)

	acr, ok := claims["acr"].(string)
	if !ok || acr != "urn:harbor:ac:webauthn" {
		t.Errorf("id_token.acr = %v, want %q", claims["acr"], "urn:harbor:ac:webauthn")
	}

	amrRaw, ok := claims["amr"].([]any)
	if !ok || len(amrRaw) != 2 {
		t.Fatalf("id_token.amr = %v, want [hwk user]", claims["amr"])
	}
	if amrRaw[0] != "hwk" || amrRaw[1] != "user" {
		t.Errorf("id_token.amr = %v, want [hwk user]", amrRaw)
	}
	// Sanity: auth_time must be set (non-zero).
	authTime, ok := claims["auth_time"].(float64)
	if !ok || authTime == 0 {
		t.Errorf("id_token.auth_time = %v, want non-zero", claims["auth_time"])
	}
}

// TestAuthorizeWithUser_UnknownMethod_NoACRInToken_E2E verifies that an unknown
// auth method results in NO acr or amr claims in the issued id_token.
func TestAuthorizeWithUser_UnknownMethod_NoACRInToken_E2E(t *testing.T) {
	svc, _ := acrAMRFlowServer(t)
	ctx := context.Background()

	now := time.Now()
	_ = now

	result, aerr := svc.AuthorizeWithUser(ctx, AuthorizeWithUserRequest{
		ClientID:            "acr-test-client",
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		State:               "s1",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		UserID:              "user-1",
		AuthMethod:          AuthMethod(""), // unknown/empty — fail-closed
	})
	if aerr != nil {
		t.Fatalf("AuthorizeWithUser: %v", aerr)
	}

	tokens, terr := svc.Token(ctx, TokenRequest{
		GrantType:    "authorization_code",
		Code:         result.Code,
		RedirectURI:  "https://example.com/callback",
		ClientID:     "acr-test-client",
		CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	})
	if terr != nil {
		t.Fatalf("Token: %v", terr)
	}

	claims := decodeIDTokenClaims(t, tokens.IDToken)

	if _, present := claims["acr"]; present {
		t.Errorf("id_token.acr = %v, want absent (fail-closed: no ACR for unknown method)", claims["acr"])
	}
	if _, present := claims["amr"]; present {
		t.Errorf("id_token.amr = %v, want absent (fail-closed: no AMR for unknown method)", claims["amr"])
	}
}
