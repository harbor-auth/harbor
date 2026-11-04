//go:build integration

package clients_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/crypto"
	db "github.com/harbor-auth/harbor/internal/gen/db"
	"github.com/harbor-auth/harbor/internal/gen/openapi"
	"github.com/harbor-auth/harbor/internal/identity"
	"github.com/harbor-auth/harbor/internal/oidc"
	"github.com/harbor-auth/harbor/internal/oidcapi"
	"github.com/harbor-auth/harbor/internal/region"
	"github.com/harbor-auth/harbor/internal/testsupport/realredis"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Boundary: real migrations, PostgreSQL grant/identifier/session/outbox stores,
// Redis codes, PPID derivation, encryption, JWT issuance and HTTP UserInfo.
// The authenticated user is supplied at the completed passkey boundary; only
// the external KMS boundary uses a local cryptographic key provider.
type scopedAuth struct{ id string }

func (a scopedAuth) AuthenticatedUserID(context.Context) (string, error) { return a.id, nil }

type scopedRevoke struct{ sessions *clients.DBSessionStore }

func (r scopedRevoke) RevokeCodeFamily(ctx context.Context, code oidc.AuthCode) error {
	return r.sessions.RevokeSessionsByGrant(ctx, code.GrantID)
}

func scopedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "scoped_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(t.Context(), "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	files, err := filepath.Glob("../../db/migrations/*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(t.Context(), string(raw)); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
	}
	return pool
}

type scopedFlow struct {
	pool     *pgxpool.Pool
	svc      *oidc.Service
	grants   *clients.DBGrantStore
	sessions *clients.DBSessionStore
	outbox   *clients.DBRevocationOutbox
	ids      *clients.DBIdentifierStore
	user     string
	server   *oidcapi.Server
	verifier *oidc.JWTVerifier
}

func newScopedFlow(t *testing.T) *scopedFlow {
	t.Helper()
	ctx := region.WithRegion(t.Context(), region.Region("EU"))
	pool := scopedPool(t)
	q := db.New(pool)
	keys, err := crypto.NewLocalKeyProvider("scoped-userinfo-test-key-at-least-32-bytes")
	if err != nil {
		t.Fatal(err)
	}
	ids := clients.NewDBIdentifierStore(pool, keys, crypto.NewCipher())
	enrol := identity.NewEnroller(keys, crypto.NewCipher(), clients.NewDBUserPersister(q))
	hash := sha256.Sum256([]byte("owner@example.com"))
	user, err := enrol.EnrollIdentified(ctx, "EU", "email", "owner@example.com", hash[:], ids)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "UPDATE users SET status='active' WHERE id=$1", user.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO relying_parties(client_id,name,token_format,token_endpoint_auth_method,sector_id,redirect_uris,scopes_allowed) VALUES ('scoped-client','Scoped test','jwt','none','site.example',ARRAY['https://site.example/cb'],ARRAY['openid','email','offline_access'])`); err != nil {
		t.Fatal(err)
	}
	grants := clients.NewDBGrantStore(q)
	sessions := clients.NewDBSessionStoreWithPool(q, pool)
	outbox := clients.NewDBRevocationOutbox(q, nil)
	registry := clients.NewDBClientRegistry(q)
	resolver := oidc.NewPPIDSessionResolver(oidc.PPIDSessionResolverConfig{Auth: scopedAuth{user.UserID}, Loader: clients.NewDBSecretLoader(q, keys, crypto.NewCipher()), Grants: grants})
	signer, err := crypto.NewLocalSigner()
	if err != nil {
		t.Fatal(err)
	}
	svc, err := oidc.NewService(oidc.ServiceConfig{Issuer: "https://eu.harbor.id", Clients: registry, Codes: clients.NewRedisAuthCodeStore(realredis.NewClient(t), time.Minute), Tokens: oidc.NewJWTIssuer(oidc.JWTIssuerConfig{Signer: signer}), Sessions: resolver, SessionStore: sessions, Grants: grants, Revocations: scopedRevoke{sessions}, Outbox: outbox})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := oidc.NewJWTVerifier(oidc.JWTVerifierConfig{Signer: signer, ExpectedIssuer: "https://eu.harbor.id"})
	if err != nil {
		t.Fatal(err)
	}
	server := oidcapi.New(oidcapi.Config{Issuer: "https://eu.harbor.id", Service: svc, Signers: []crypto.Signer{signer}, Grants: grants, Clients: registry, UserInfoSource: ids, LogoutVerifier: verifier, SessionRevoker: sessions})
	return &scopedFlow{pool, svc, grants, sessions, outbox, ids, user.UserID, server, verifier}
}

const scopedVerifier = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

func (f *scopedFlow) approve(t *testing.T, scope string) {
	t.Helper()
	if err := f.svc.ApproveConsent(region.WithRegion(t.Context(), region.Region("EU")), f.user, "scoped-client", scope); err != nil {
		t.Fatal(err)
	}
}
func (f *scopedFlow) code(t *testing.T, scope string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(scopedVerifier))
	result, err := f.svc.AuthorizeWithUser(region.WithRegion(t.Context(), region.Region("EU")), oidc.AuthorizeWithUserRequest{ClientID: "scoped-client", RedirectURI: "https://site.example/cb", Scope: scope, State: "csrf", CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:]), CodeChallengeMethod: "S256", UserID: f.user, AuthMethod: oidc.AuthMethodWebAuthn})
	if err != nil {
		t.Fatal(err)
	}
	return result.Code
}
func scopedTokenReq(code string) oidc.TokenRequest {
	return oidc.TokenRequest{GrantType: "authorization_code", Code: code, ClientID: "scoped-client", RedirectURI: "https://site.example/cb", CodeVerifier: scopedVerifier}
}
func (f *scopedFlow) token(t *testing.T, scope string) *oidc.IssuedTokens {
	t.Helper()
	tokens, err := f.svc.Token(t.Context(), scopedTokenReq(f.code(t, scope)))
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}
func (f *scopedFlow) info(t *testing.T, token, reg string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://eu.harbor.id/userinfo", nil)
	req = req.WithContext(region.WithRegion(req.Context(), region.Region(reg)))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	f.server.GetUserInfo(w, req)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("userinfo cached")
	}
	return w.Code, body
}

//harbor:invariant INV-REFRESH-SCOPE-REFLECTS-GRANT
func TestScopedUserInfoConsentAndLifetime(t *testing.T) {
	f := newScopedFlow(t)
	ctx := region.WithRegion(t.Context(), region.Region("EU"))
	if _, err := f.svc.AuthorizeWithUser(ctx, oidc.AuthorizeWithUserRequest{ClientID: "scoped-client", RedirectURI: "https://site.example/cb", Scope: "openid email", State: "csrf", CodeChallenge: scopedVerifier, CodeChallengeMethod: "S256", UserID: f.user}); err == nil {
		t.Fatal("authorization silently approved consent")
	}
	f.approve(t, "openid offline_access")
	limited := f.token(t, "openid offline_access")
	if status, body := f.info(t, limited.AccessToken, "EU"); status != 200 || body["email"] != nil {
		t.Fatalf("unexpected limited disclosure: %d %v", status, body)
	}
	// Expansion must not retroactively expand an existing token or refresh family.
	f.approve(t, "openid email offline_access")
	if status, body := f.info(t, limited.AccessToken, "EU"); status != 200 || body["email"] != nil {
		t.Fatalf("old access token expanded: %d %v", status, body)
	}
	refreshed, terr := f.svc.Refresh(ctx, oidc.TokenRequest{GrantType: "refresh_token", ClientID: "scoped-client", RefreshToken: limited.RefreshToken})
	if terr != nil {
		t.Fatal(terr)
	}
	if strings.Contains(refreshed.Scope, "email") {
		t.Fatal("old refresh family gained email")
	}
	spentCode := f.code(t, "openid email offline_access")
	shared, sharedErr := f.svc.Token(ctx, scopedTokenReq(spentCode))
	if sharedErr != nil {
		t.Fatal(sharedErr)
	}
	status, body := f.info(t, shared.AccessToken, "EU")
	if status != 200 || body["email"] != "owner@example.com" || body["email_verified"] != true {
		t.Fatalf("verified email missing: %d %v", status, body)
	}
	for _, token := range []string{shared.IDToken, shared.AccessToken} {
		parts := strings.Split(token, ".")
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		var claims map[string]any
		if err = json.Unmarshal(raw, &claims); err != nil {
			t.Fatal(err)
		}
		if claims["email"] != nil || claims["email_verified"] != nil || claims["user_id"] != nil {
			t.Fatal("personal claims leaked into JWT")
		}
	}
	if status, _ = f.info(t, shared.AccessToken, "US"); status != 401 {
		t.Fatal("cross-region claim disclosure")
	}
	grant, found, err := f.grants.FindGrant(ctx, f.user, "scoped-client")
	if err != nil || !found {
		t.Fatal(err)
	}
	staleCode := f.code(t, "openid email")
	if _, err = f.grants.RevokeGrantAndSessions(ctx, grant.ID); err != nil {
		t.Fatal(err)
	}
	f.approve(t, "openid email offline_access")
	replacement := f.token(t, "openid email offline_access")
	next, found, err := f.grants.FindGrant(ctx, f.user, "scoped-client")
	if err != nil || !found {
		t.Fatal(err)
	}
	if grant.ID == next.ID || grant.PairwiseSub != next.PairwiseSub {
		t.Fatal("reconnect must change lifetime, retain PPID")
	}
	if status, _ = f.info(t, shared.AccessToken, "EU"); status != 401 {
		t.Fatal("old access token followed replacement grant")
	}
	if _, err := f.svc.Token(ctx, scopedTokenReq(staleCode)); err == nil {
		t.Fatal("old code followed replacement grant")
	}
	intro := oidc.NewIntrospector(oidc.IntrospectConfig{Verifier: f.verifier, Grants: f.grants, Clients: clients.NewDBClientRegistry(db.New(f.pool))})
	if intro.Introspect(ctx, oidc.IntrospectRequest{Token: shared.AccessToken, ClientID: "scoped-client"}).Active {
		t.Fatal("introspection followed replacement grant")
	}
	if !intro.Introspect(ctx, oidc.IntrospectRequest{Token: replacement.AccessToken, ClientID: "scoped-client"}).Active {
		t.Fatal("replacement introspection inactive")
	}
	if _, terr := f.svc.Token(ctx, scopedTokenReq(spentCode)); terr == nil {
		t.Fatal("spent old code replay accepted")
	}
	logout := httptest.NewRecorder()
	f.server.GetEndSession(logout, httptest.NewRequest("GET", "https://eu.harbor.id/end_session", nil).WithContext(ctx), openapi.GetEndSessionParams{IdTokenHint: shared.IDToken})
	if err := f.svc.RevokeRefreshToken(ctx, shared.RefreshToken, "scoped-client"); err != nil {
		t.Fatal(err)
	}
	// Authenticated old token replay and durable delivery affect only the old ID.
	if _, err := f.svc.Refresh(ctx, oidc.TokenRequest{GrantType: "refresh_token", ClientID: "scoped-client", RefreshToken: shared.RefreshToken}); err == nil {
		t.Fatal("revoked refresh worked")
	}
	if err = f.outbox.DeliverPending(ctx, f.sessions); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Refresh(ctx, oidc.TokenRequest{GrantType: "refresh_token", ClientID: "scoped-client", RefreshToken: replacement.RefreshToken}); err != nil {
		t.Fatalf("old replay revoked replacement: %v", err)
	}
	if _, err = f.pool.Exec(ctx, "UPDATE users SET status='locked' WHERE id=$1", f.user); err != nil {
		t.Fatal(err)
	}
	if status, _ = f.info(t, replacement.AccessToken, "EU"); status != 401 {
		t.Fatal("locked account disclosed claims")
	}
}

func TestScopedUserInfoLegacyConsentAndConcurrentApproval(t *testing.T) {
	f := newScopedFlow(t)
	ctx := region.WithRegion(t.Context(), region.Region("EU"))
	f.approve(t, "openid")
	if _, err := f.pool.Exec(ctx, "UPDATE grants SET scopes=ARRAY['openid','email'],email_consent=false WHERE user_id=$1", f.user); err != nil {
		t.Fatal(err)
	}
	required, err := f.svc.ConsentRequired(ctx, f.user, "scoped-client", "openid email", "")
	if err != nil || !required {
		t.Fatal("legacy relay consent authorized real email")
	}
	if _, err := f.svc.ConsentRequired(ctx, f.user, "scoped-client", "openid email", "none"); err == nil {
		t.Fatal("silent real-email upgrade")
	}
	var wg sync.WaitGroup
	failures := make(chan error, 12)
	for i := range 12 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			scope := "openid email"
			if i%2 == 0 {
				scope = "openid offline_access"
			}
			if err := f.svc.ApproveConsent(ctx, f.user, "scoped-client", scope); err != nil {
				failures <- err
			}
		}(i)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	grants, err2 := f.grants.ListGrantsByUser(ctx, f.user)
	if err2 != nil || len(grants) != 1 {
		t.Fatalf("concurrent approvals: %v %v", grants, err2)
	}
	if !grants[0].EmailConsent || len(grants[0].Scopes) != 3 {
		t.Fatalf("lost approval: %v", grants[0].Scopes)
	}
	tokens := f.token(t, "openid email")
	if status, body := f.info(t, tokens.AccessToken, "EU"); status != 200 || body["email"] == nil {
		t.Fatalf("fresh consent failed: %d %v", status, body)
	}
	// Optional email is absent for accounts without a verified identifier.
	if _, err := f.pool.Exec(ctx, "DELETE FROM account_identifiers WHERE user_id=$1", f.user); err != nil {
		t.Fatal(err)
	}
	if status, body := f.info(t, tokens.AccessToken, "EU"); status != 200 || body["email"] != nil || body["email_verified"] != nil {
		t.Fatalf("invented email: %d %v", status, body)
	}
}

func TestScopedRefreshSessionPersistsEmptyAndRealAuthenticationContext(t *testing.T) {
	f := newScopedFlow(t)
	f.approve(t, "openid offline_access")
	grant, found, err := f.grants.FindGrant(t.Context(), f.user, "scoped-client")
	if err != nil || !found {
		t.Fatal(err)
	}
	for _, amr := range [][]string{nil, {"webauthn"}} {
		id := uuid.NewString()
		hash := sha256.Sum256([]byte(id))
		session := oidc.RefreshSession{ID: id, Region: grant.Region, UserID: f.user, ClientID: grant.ClientID, GrantID: grant.ID, Scopes: []string{"openid", "offline_access"}, TokenHash: hash[:], ExpiresAt: time.Now().Add(time.Hour), AuthTime: time.Now().Unix(), ACR: "test-acr", AMR: amr}
		if err := f.sessions.CreateSession(t.Context(), session); err != nil {
			t.Fatal(err)
		}
		stored, err := f.sessions.GetSessionByTokenHash(t.Context(), hash[:])
		if err != nil {
			t.Fatal(err)
		}
		if stored.AuthTime != session.AuthTime || stored.ACR != session.ACR || len(stored.AMR) != len(amr) {
			t.Fatal("lost authentication context")
		}
		next := session
		next.ID = uuid.NewString()
		nextHash := sha256.Sum256([]byte(next.ID))
		next.TokenHash = nextHash[:]
		if err := f.sessions.RotateSession(t.Context(), session.ID, next); err != nil {
			t.Fatal(err)
		}
	}
}

func TestScopedUserInfoHonorsApplicationPolicy(t *testing.T) {
	f := newScopedFlow(t)
	f.approve(t, "openid email offline_access")
	tokens := f.token(t, "openid email offline_access")
	intro := oidc.NewIntrospector(oidc.IntrospectConfig{Verifier: f.verifier, Grants: f.grants, Clients: clients.NewDBClientRegistry(db.New(f.pool))})
	if _, err := f.pool.Exec(t.Context(), "UPDATE relying_parties SET scopes_allowed=ARRAY['openid','offline_access'] WHERE client_id='scoped-client'"); err != nil {
		t.Fatal(err)
	}
	if status, body := f.info(t, tokens.AccessToken, "EU"); status != 200 || body["email"] != nil {
		t.Fatalf("application policy ignored: %d %v", status, body)
	}
	if intro.Introspect(t.Context(), oidc.IntrospectRequest{Token: tokens.AccessToken, ClientID: "scoped-client"}).Active {
		t.Fatal("introspection ignored application scope removal")
	}
	refreshed, terr := f.svc.Refresh(t.Context(), oidc.TokenRequest{GrantType: "refresh_token", ClientID: "scoped-client", RefreshToken: tokens.RefreshToken})
	if terr != nil {
		t.Fatal(terr)
	}
	if strings.Contains(refreshed.Scope, "email") {
		t.Fatal("refresh ignored application scope removal")
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE relying_parties SET deleted_at=now() WHERE client_id='scoped-client'"); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.info(t, refreshed.AccessToken, "EU"); status != 401 {
		t.Fatal("deleted application disclosed claims")
	}
	if intro.Introspect(t.Context(), oidc.IntrospectRequest{Token: refreshed.AccessToken, ClientID: "scoped-client"}).Active {
		t.Fatal("deleted application token introspected active")
	}
}
