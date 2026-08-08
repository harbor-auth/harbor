package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/cloudapi"
	db "github.com/harbor-auth/harbor/internal/gen/db"
)

// --- fake querier -----------------------------------------------------
//
// cloudapi.Store's backing "querier" interface is unexported, but its method
// set is nameable from any package (every method name is exported and every
// parameter/return type comes from internal/gen/db), so a fake satisfying it
// structurally is enough to construct a real *cloudapi.Store without a
// database. Every test in this file only exercises the auth/scope/rate-limit
// rejection paths ahead of the handler, so these methods are never actually
// called; they panic if they are, so a change that starts reaching the store
// fails loudly instead of silently returning zero values.
type unusedCloudQuerier struct{}

func (unusedCloudQuerier) CreateCloudNamespace(context.Context, db.CreateCloudNamespaceParams) (db.CloudNamespace, error) {
	panic("unusedCloudQuerier: CreateCloudNamespace should not be reached in wiring tests")
}

func (unusedCloudQuerier) GetCloudNamespace(context.Context, string) (db.CloudNamespace, error) {
	panic("unusedCloudQuerier: GetCloudNamespace should not be reached in wiring tests")
}

func (unusedCloudQuerier) SoftDeleteCloudNamespace(context.Context, string) error {
	panic("unusedCloudQuerier: SoftDeleteCloudNamespace should not be reached in wiring tests")
}

func (unusedCloudQuerier) CreateCloudOperation(context.Context, db.CreateCloudOperationParams) (db.CloudOperation, error) {
	panic("unusedCloudQuerier: CreateCloudOperation should not be reached in wiring tests")
}

func (unusedCloudQuerier) GetCloudOperation(context.Context, db.GetCloudOperationParams) (db.CloudOperation, error) {
	panic("unusedCloudQuerier: GetCloudOperation should not be reached in wiring tests")
}

func (unusedCloudQuerier) CreateCloudSession(context.Context, db.CreateCloudSessionParams) (db.CloudSession, error) {
	panic("unusedCloudQuerier: CreateCloudSession should not be reached in wiring tests")
}

func (unusedCloudQuerier) GetCloudSession(context.Context, string) (db.CloudSession, error) {
	panic("unusedCloudQuerier: GetCloudSession should not be reached in wiring tests")
}

// unusedCloudClientStore is unusedCloudQuerier's counterpart for
// cloudapi.ClientProvisioningStore: every method panics, so these wiring
// tests fail loudly if a request ever reaches past auth/scope/rate-limit
// into the actual client-provisioning handler logic.
type unusedCloudClientStore struct{}

func (unusedCloudClientStore) Create(context.Context, clients.NewNamespacedClient) (clients.NamespacedClient, error) {
	panic("unusedCloudClientStore: Create should not be reached in wiring tests")
}

func (unusedCloudClientStore) Get(context.Context, string, string) (clients.NamespacedClient, error) {
	panic("unusedCloudClientStore: Get should not be reached in wiring tests")
}

func (unusedCloudClientStore) List(context.Context, string) ([]clients.NamespacedClient, error) {
	panic("unusedCloudClientStore: List should not be reached in wiring tests")
}

func (unusedCloudClientStore) Update(context.Context, clients.UpdateNamespacedClient) (clients.NamespacedClient, error) {
	panic("unusedCloudClientStore: Update should not be reached in wiring tests")
}

func (unusedCloudClientStore) SoftDelete(context.Context, string, string) error {
	panic("unusedCloudClientStore: SoftDelete should not be reached in wiring tests")
}

// --- fake rate limiter --------------------------------------------------

type fakeRateLimiter struct {
	allowed bool
	err     error
}

func (f fakeRateLimiter) Allow(context.Context, string) (bool, time.Duration, error) {
	return f.allowed, 0, f.err
}

func alwaysAllow() clients.RateLimiter { return fakeRateLimiter{allowed: true} }

// --- test JWT signing helpers (mirrors internal/cloudapi/serviceauth_test.go) ---

func cloudTestEncodeSegment(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func cloudTestSignES256(t *testing.T, priv *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	signingInput := cloudTestEncodeSegment(t, header) + "." + cloudTestEncodeSegment(t, claims)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// cloudTestEnv bundles a *cloudapi.ServiceAuthVerifier wired to a fresh ES256
// trust anchor and miniredis-backed replay guard, a *cloudapi.Store over the
// panicking fake querier, and a *cloudapi.KeysHandler — enough to exercise
// registerCloudAPIRoutes end-to-end without a real database.
type cloudTestEnv struct {
	verifier    *cloudapi.ServiceAuthVerifier
	store       *cloudapi.Store
	clientStore cloudapi.ClientProvisioningStore
	keys        *cloudapi.KeysHandler
	ecPriv      *ecdsa.PrivateKey
	now         time.Time
}

func newCloudTestEnv(t *testing.T) *cloudTestEnv {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() }) //nolint:errcheck // test cleanup; error not actionable

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	verifier, err := cloudapi.NewServiceAuthVerifier(cloudapi.ServiceAuthVerifierConfig{
		PublicKeyPEM: pubPEM,
		ReplayGuard:  cloudapi.NewRedisReplayGuard(redisClient),
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewServiceAuthVerifier: %v", err)
	}

	store := cloudapi.NewStore(unusedCloudQuerier{})
	clientStore := unusedCloudClientStore{}
	keys := cloudapi.NewKeysHandler(verifier, "http://harbor-hot.internal:8080", "cloud-proxy-token", nil)

	return &cloudTestEnv{verifier: verifier, store: store, clientStore: clientStore, keys: keys, ecPriv: priv, now: now}
}

// token mints a cloudServiceAuth bearer JWT valid against env's trust anchor.
// scope is the space-delimited scope claim; jti defaults to a fresh value per
// call so repeated calls in one test don't spuriously collide as replays.
func (e *cloudTestEnv) token(t *testing.T, scope, jti string) string {
	t.Helper()
	claims := map[string]any{
		"iss":   "harbor-cloud",
		"sub":   "harbor-cloud-svc-1",
		"aud":   cloudapi.ExpectedAudience,
		"scope": scope,
		"exp":   e.now.Add(90 * time.Second).Unix(),
		"iat":   e.now.Unix(),
		"jti":   jti,
	}
	return cloudTestSignES256(t, e.ecPriv, map[string]any{"alg": "ES256", "typ": "JWT"}, claims)
}

func (e *cloudTestEnv) mux(t *testing.T, limiters cloudAPILimiters) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	registerCloudAPIRoutes(mux, e.verifier, e.store, e.clientStore, e.keys, limiters)
	return mux
}

func allowAllLimiters() cloudAPILimiters {
	return cloudAPILimiters{
		sessionsMint:     alwaysAllow(),
		namespacesCreate: alwaysAllow(),
		namespacesGet:    alwaysAllow(),
		namespacesDelete: alwaysAllow(),
		clientsCreate:    alwaysAllow(),
		clientsRead:      alwaysAllow(),
		clientsUpdate:    alwaysAllow(),
		clientsDelete:    alwaysAllow(),
		keysRotate:       alwaysAllow(),
	}
}

// cloudAuthedRoutes are the nine routes registerCloudAPIRoutes wraps in
// cloudAuthorized (i.e. every route except keys/rotate, which self-verifies —
// see registerCloudAPIRoutes's comment).
var cloudAuthedRoutes = []struct {
	name   string
	method string
	path   string
	scope  string
}{
	{"sessions mint", http.MethodPost, "/admin/v1/sessions", scopeSessionsMint},
	{"namespaces create", http.MethodPost, "/admin/v1/namespaces", scopeNamespacesWrite},
	{"namespaces get", http.MethodGet, "/admin/v1/namespaces/ns-1", scopeNamespacesRead},
	{"namespaces delete", http.MethodDelete, "/admin/v1/namespaces/ns-1", scopeNamespacesWrite},
	{"clients create", http.MethodPost, "/admin/v1/namespaces/ns-1/clients", scopeClientsWrite},
	{"clients list", http.MethodGet, "/admin/v1/namespaces/ns-1/clients", scopeClientsRead},
	{"clients get", http.MethodGet, "/admin/v1/namespaces/ns-1/clients/client-1", scopeClientsRead},
	{"clients update", http.MethodPut, "/admin/v1/namespaces/ns-1/clients/client-1", scopeClientsWrite},
	{"clients delete", http.MethodDelete, "/admin/v1/namespaces/ns-1/clients/client-1", scopeClientsWrite},
}

func TestRegisterCloudAPIRoutesRejectsMissingBearer(t *testing.T) {
	env := newCloudTestEnv(t)
	mux := env.mux(t, allowAllLimiters())

	for _, rt := range cloudAuthedRoutes {
		t.Run(rt.name, func(t *testing.T) {
			req := httptest.NewRequest(rt.method, rt.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
			}
			assertCloudErrorCode(t, rec, "invalid_token")
		})
	}
}

func TestRegisterCloudAPIRoutesRejectsWrongScope(t *testing.T) {
	env := newCloudTestEnv(t)
	mux := env.mux(t, allowAllLimiters())

	for i, rt := range cloudAuthedRoutes {
		t.Run(rt.name, func(t *testing.T) {
			// A token scoped for an unrelated operation, never rt.scope.
			token := env.token(t, "keys:rotate", fmt.Sprintf("jti-wrong-scope-%d", i))
			req := httptest.NewRequest(rt.method, rt.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			assertCloudErrorCode(t, rec, "insufficient_scope")
		})
	}
}

func TestRegisterCloudAPIRoutesAcceptsCorrectScopePastAuth(t *testing.T) {
	// Proves cloudAuthorized actually calls through to the handler on a
	// valid, correctly-scoped token — the request then reaches the fake
	// store/handler, which panics (by design; see unusedCloudQuerier) rather
	// than silently succeeding, so a panic recovered as a 500-shaped failure
	// here is the *expected* signal that auth passed, not a wiring bug.
	env := newCloudTestEnv(t)
	mux := env.mux(t, allowAllLimiters())

	token := env.token(t, scopeNamespacesRead, "jti-correct-scope")
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/namespaces/ns-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("expected the fake store to panic once auth/scope checks pass and the handler is reached")
		}
	}()
	mux.ServeHTTP(rec, req)
}

func TestRegisterCloudAPIRoutesFailsClosedWhenRateLimiterErrors(t *testing.T) {
	env := newCloudTestEnv(t)
	limiters := allowAllLimiters()
	limiters.namespacesGet = fakeRateLimiter{allowed: false, err: errors.New("redis: connection refused")}
	mux := env.mux(t, limiters)

	// No bearer token at all: if the rate limiter is checked first (as
	// registerCloudAPIRoutes wires it), the backend error must still deny
	// with 429 rather than ever reaching the auth check (which would 401).
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/namespaces/ns-1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusTooManyRequests, rec.Body.String())
	}
	assertCloudErrorCode(t, rec, "rate_limited")
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected a Retry-After header on a rate-limited response")
	}
}

func TestRegisterCloudAPIRoutesFailsClosedWhenRateLimiterOverLimit(t *testing.T) {
	env := newCloudTestEnv(t)
	limiters := allowAllLimiters()
	limiters.sessionsMint = fakeRateLimiter{allowed: false, err: nil}
	mux := env.mux(t, limiters)

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/sessions", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusTooManyRequests, rec.Body.String())
	}
}

func TestRegisterCloudAPIRoutesKeysRotateSelfAuthenticatesAndIsRateLimited(t *testing.T) {
	env := newCloudTestEnv(t)

	t.Run("rate limited before reaching the handler's own auth check", func(t *testing.T) {
		limiters := allowAllLimiters()
		limiters.keysRotate = fakeRateLimiter{allowed: false}
		mux := env.mux(t, limiters)

		req := httptest.NewRequest(http.MethodPost, "/admin/v1/keys/rotate", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusTooManyRequests, rec.Body.String())
		}
	})

	t.Run("missing bearer rejected by the handler's own verifier, not double-verified", func(t *testing.T) {
		mux := env.mux(t, allowAllLimiters())
		req := httptest.NewRequest(http.MethodPost, "/admin/v1/keys/rotate", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
		}
	})

	t.Run("a correctly-scoped token is not rejected as replayed by a redundant outer verify", func(t *testing.T) {
		// Regression guard for the exact bug registerCloudAPIRoutes's comment
		// warns about: if keys/rotate were (re-)wrapped in cloudAuthorized,
		// this request would 401 token_replayed on its second (handler-internal)
		// Verify call instead of proceeding to the (fake, unreachable) proxy call.
		mux := env.mux(t, allowAllLimiters())
		token := env.token(t, "keys:rotate", "jti-keys-rotate-1")
		req := httptest.NewRequest(http.MethodPost, "/admin/v1/keys/rotate", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		// The fake harbor-hot at "http://harbor-hot.internal:8080" doesn't
		// exist in this test process, so the proxied call fails and
		// PostKeysRotate reports 500 server_error — the point here is that it
		// is NOT 401 token_replayed, proving auth ran exactly once.
		if rec.Code == http.StatusUnauthorized {
			t.Fatalf("keys/rotate rejected a fresh token as unauthorized (want it to reach the proxy call): body = %s", rec.Body.String())
		}
	})
}

// assertCloudErrorCode decodes rec's body as the shared cloudapi Error
// envelope and asserts its Code field.
func assertCloudErrorCode(t *testing.T, rec *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if body.Code != wantCode {
		t.Errorf("error code = %q, want %q", body.Code, wantCode)
	}
}
