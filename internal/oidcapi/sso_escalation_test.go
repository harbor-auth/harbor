package oidcapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/harbor-auth/harbor/internal/bff"
	"github.com/harbor-auth/harbor/internal/oidc"

	bfftest "github.com/harbor-auth/harbor/internal/testsupport/bff"
)

// panicWebAuthnService is a bff.WebAuthnService stub whose methods panic if
// called. Used below to prove the browser-nonce gate refuses an SSO-minted
// session BEFORE ever reaching WebAuthn ceremony logic — a panic recovered
// here would mean the test itself is broken, not the production code.
type panicWebAuthnService struct{}

func (panicWebAuthnService) BeginLogin(context.Context, []byte) (*protocol.CredentialAssertion, string, error) {
	panic("panicWebAuthnService: BeginLogin should not be reached — the nonce gate must reject first")
}

func (panicWebAuthnService) FinishLogin(context.Context, string, *protocol.ParsedCredentialAssertionData) (string, bool, error) {
	panic("panicWebAuthnService: FinishLogin should not be reached — the nonce gate must reject first")
}

func (panicWebAuthnService) BeginDiscoverableLogin(context.Context) (*protocol.CredentialAssertion, string, error) {
	panic("panicWebAuthnService: BeginDiscoverableLogin should not be reached — the nonce gate must reject first")
}

func (panicWebAuthnService) FinishDiscoverableLogin(context.Context, string, *protocol.ParsedCredentialAssertionData) (string, bool, error) {
	panic("panicWebAuthnService: FinishDiscoverableLogin should not be reached — the nonce gate must reject first")
}

// ssoShapedSession builds a BFFSessionRecord exactly the way
// cmd/harbor-mgmt/sso.go's wireSSOLoginRoute constructs one: full scope,
// recovery not required, federated auth method, and — the property under
// test — a nil BrowserNonceHash.
func ssoShapedSession(requestID, userID string) bff.BFFSessionRecord {
	return bff.BFFSessionRecord{
		RequestID:        requestID,
		UserID:           userID,
		SessionScope:     bff.SessionScopeFull,
		RecoveryRequired: false,
		AuthMethod:       oidc.AuthMethodFederated,
		BrowserNonceHash: nil,
		ExpiresAt:        time.Now().Add(5 * time.Minute),
	}
}

// TestSSOMintedSessionCannotCompleteOIDCAuthorization is the escalation test
// the whole design earns: an SSO-minted session (no BrowserNonceHash — see
// cmd/harbor-mgmt/sso.go's wireSSOLoginRoute) is fed to the THREE entry
// points that could otherwise turn it into a forged OIDC login —
// bff.LoginHandler.BeginLogin, bff.LoginHandler.FinishLoginWithParsedData,
// and Server.GetAuthorizeComplete — and each one MUST refuse it. This is the
// actual security boundary a compromised harbor-cloud is up against: it can
// mint login codes for arbitrary users (landing them on the Harbor
// dashboard), but it can never forge a login to a relying party.
//
//harbor:invariant INV-CLOUDAPI-SERVICE-AUTH
func TestSSOMintedSessionCannotCompleteOIDCAuthorization(t *testing.T) {
	t.Run("BeginLogin refuses", func(t *testing.T) {
		store := bfftest.NewInMemoryBFFSessionStore()
		if err := store.Create(context.Background(), ssoShapedSession("sso-req-1", "user-abc-123")); err != nil {
			t.Fatalf("seed session: %v", err)
		}
		handler := bff.NewLoginHandler(store, panicWebAuthnService{}, bff.DiscoverableUserResolver{}, testLoginURL)

		req := httptest.NewRequest(http.MethodGet, "/login?request_id=sso-req-1", nil)
		rec := httptest.NewRecorder()
		handler.BeginLogin(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("BeginLogin status = %d, want 400 (nonce gate must refuse an SSO-minted session); body = %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("FinishLoginWithParsedData refuses", func(t *testing.T) {
		store := bfftest.NewInMemoryBFFSessionStore()
		if err := store.Create(context.Background(), ssoShapedSession("sso-req-2", "user-abc-123")); err != nil {
			t.Fatalf("seed session: %v", err)
		}
		handler := bff.NewLoginHandler(store, panicWebAuthnService{}, bff.DiscoverableUserResolver{}, testLoginURL)

		req := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
		req.AddCookie(&http.Cookie{Name: bff.CookieName, Value: "sso-req-2"})
		rec := httptest.NewRecorder()
		handler.FinishLoginWithParsedData(rec, req, nil)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("FinishLoginWithParsedData status = %d, want 400 (nonce gate must refuse an SSO-minted session); body = %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("GetAuthorizeComplete refuses", func(t *testing.T) {
		store := bfftest.NewInMemoryBFFSessionStore()
		record := ssoShapedSession("sso-req-3", "user-abc-123")
		record.ClientID = testClientID
		record.RedirectURI = testRedirectURI
		record.Scope = "openid profile"
		record.State = testState
		if err := store.Create(context.Background(), record); err != nil {
			t.Fatalf("seed session: %v", err)
		}
		ts := newBFFFlowServerWithStore(t, store)

		res := getAuthorizeCompleteWithCookie(t, ts, "sso-req-3", nil)
		defer func() { _ = res.Body.Close() }()

		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("GetAuthorizeComplete status = %d, want 400 (error page, no code) for an SSO-minted session", res.StatusCode)
		}
		if loc := res.Header.Get("Location"); loc != "" {
			t.Fatalf("GetAuthorizeComplete must never redirect an SSO-minted session to the RP, got Location: %q", loc)
		}
	})
}
