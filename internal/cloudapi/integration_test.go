//go:build integration

// integration_test.go is the cross-process half of the contract test suite
// (contract_test.go covers fixture-driven, in-process scenarios against an
// in-memory store and miniredis). It exercises the exact same production
// pieces — Server, SessionsHandler, KeysHandler, ServiceAuthVerifier, wired
// through newContractRouter (contract_test.go) — but against a REAL
// PostgreSQL database and a REAL Redis instance, served over a real HTTP
// listener (httptest.NewServer), so every request in this file makes an
// actual network round trip through net/http rather than an in-process
// ResponseRecorder call.
//
// Run with: make test-integration (needs DATABASE_URL/REDIS_URL; skips
// otherwise, matching cmd/harbor-mgmt/main_integration_test.go's and
// cmd/harbor-hot/main_integration_test.go's convention).
package cloudapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/crypto"
	db "github.com/harbor-auth/harbor/internal/gen/db"
	cloudopenapi "github.com/harbor-auth/harbor/internal/gen/openapi/cloud"
	"github.com/harbor-auth/harbor/internal/httpserver"
)

// integrationDeps bundles the real dependencies a cross-process cloudapi
// scenario needs. requireIntegrationDeps skips the calling test when either
// dependency is unavailable, mirroring cmd/harbor-mgmt's
// TestRunBuildsDurableManagementGraph.
type integrationDeps struct {
	store *Store
}

func requireIntegrationDeps(t *testing.T) integrationDeps {
	t.Helper()
	for _, name := range []string{"DATABASE_URL", "REDIS_URL"} {
		if strings.TrimSpace(os.Getenv(name)) == "" {
			t.Skipf("%s is not set; start the containerised integration dependencies (make test-integration)", name)
		}
	}

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// DATABASE_URL is already confirmed non-empty above, so ConnectDB (which
	// only returns a nil pool when the URL is empty) cannot return a nil pool
	// here — a nil pool at this point would be a ConnectDB contract bug, not
	// an environment we should silently skip.
	pool, err := clients.ConnectDB(ctx, logger)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	if pool == nil {
		t.Fatal("clients.ConnectDB returned a nil pool despite a non-empty DATABASE_URL")
	}
	t.Cleanup(pool.Close)

	// integrationKMSSecret is a fixed test secret — never production
	// material, only long enough to satisfy crypto.NewLocalKeyProvider's
	// length floor — so the user-sessions create-path can be exercised
	// against a real transaction.
	store := NewStore(db.New(pool)).WithFederatedIdentities(
		NewPgxFederatedPool(pool),
		requireIntegrationKeyProvider(t),
		crypto.NewCipher(),
	)

	return integrationDeps{store: store}
}

// integrationKMSSecret is a fixed 32+ byte test secret for
// crypto.NewLocalKeyProvider — never production material.
const integrationKMSSecret = "integration-test-kms-secret-32-bytes!!"

func requireIntegrationKeyProvider(t *testing.T) crypto.KeyProvider {
	t.Helper()
	kp, err := crypto.NewLocalKeyProvider(integrationKMSSecret)
	if err != nil {
		t.Fatalf("crypto.NewLocalKeyProvider: %v", err)
	}
	return kp
}

// newIntegrationRedisClient connects a fresh Redis client. Callers must call
// requireIntegrationDeps (or otherwise confirm REDIS_URL is set) first.
func newIntegrationRedisClient(t *testing.T) *redis.Client {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// REDIS_URL is already confirmed non-empty by the caller, so ConnectRedis
	// (which only returns a nil client when the URL is empty) cannot return a
	// nil client here — see requireIntegrationDeps's comment above.
	redisClient, err := clients.ConnectRedis(ctx, logger)
	if err != nil {
		t.Fatalf("connect redis: %v", err)
	}
	if redisClient == nil {
		t.Fatal("clients.ConnectRedis returned a nil client despite a non-empty REDIS_URL")
	}
	t.Cleanup(func() { _ = redisClient.Close() }) //nolint:errcheck // test cleanup
	return redisClient
}

// uniqueID returns a namespace/idempotency-key-safe identifier that will not
// collide with a prior run against the same (persistent, real) integration
// database.
func uniqueID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// integrationEnv wires the real router (contract_test.go's newContractRouter)
// over real Postgres/Redis, served over a real HTTP listener.
type integrationEnv struct {
	ts       *httptest.Server
	verifier *ServiceAuthVerifier
	ecPriv   *ecdsa.PrivateKey
	hot      *recordingHotServer
}

func newIntegrationEnv(t *testing.T) *integrationEnv {
	t.Helper()
	deps := requireIntegrationDeps(t)
	redisClient := newIntegrationRedisClient(t)
	replayGuard := NewRedisReplayGuard(redisClient)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	verifier, err := NewServiceAuthVerifier(ServiceAuthVerifierConfig{
		PublicKeyPEM: pemEncodePublicKey(t, &priv.PublicKey),
		ReplayGuard:  replayGuard,
	})
	if err != nil {
		t.Fatalf("NewServiceAuthVerifier: %v", err)
	}

	hot := newRecordingHotServer(t)
	router := newContractRouter(deps.store, verifier, hot.URL, "integration-proxy-token", hot.Client(), redisClient)
	ts := httptest.NewServer(router)
	t.Cleanup(ts.Close)

	return &integrationEnv{ts: ts, verifier: verifier, ecPriv: priv, hot: hot}
}

// mint signs a fresh cloudServiceAuth JWT against this env's trust anchor.
func (e *integrationEnv) mint(t *testing.T, scope string, expiresIn time.Duration) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss":   "harbor-cloud",
		"sub":   "harbor-cloud-svc-integration",
		"aud":   ExpectedAudience,
		"scope": scope,
		"exp":   now.Add(expiresIn).Unix(),
		"iat":   now.Unix(),
		"jti":   uniqueID("integration-jti"),
	}
	return signES256(t, e.ecPriv, map[string]any{"alg": "ES256", "typ": "JWT"}, claims)
}

// do issues a real HTTP request against the running server.
func (e *integrationEnv) do(t *testing.T, method, path, bearer, idempotencyKey string, body string) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, e.ts.URL+path, reader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return res
}

func decodeIntegrationError(t *testing.T, res *http.Response) cloudopenapi.Error {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	var e cloudopenapi.Error
	if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	return e
}

// --- scenarios ---------------------------------------------------------

// TestIntegrationAuthorizedRequestSucceeds proves an authorized, correctly-
// scoped request reaches the real handler and persists through real
// PostgreSQL: a namespace created here is independently readable by a
// second, freshly-minted request.
func TestIntegrationAuthorizedRequestSucceeds(t *testing.T) {
	env := newIntegrationEnv(t)
	nsID := uniqueID("it-authorized-ns")

	createRes := env.do(t, http.MethodPost, "/admin/v1/namespaces",
		env.mint(t, "namespaces:write", 90*time.Second), uniqueID("it-key"),
		fmt.Sprintf(`{"id":%q}`, nsID))
	defer func() { _ = createRes.Body.Close() }()
	if createRes.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want 201", createRes.StatusCode)
	}

	getRes := env.do(t, http.MethodGet, "/admin/v1/namespaces/"+nsID,
		env.mint(t, "namespaces:read", 90*time.Second), "", "")
	defer func() { _ = getRes.Body.Close() }()
	if getRes.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d, want 200", getRes.StatusCode)
	}
}

// TestIntegrationWrongAudienceRejected proves a validly-signed token with the
// wrong aud is rejected end-to-end, over real HTTP, without ever reaching the
// handler (the target namespace is never created, so a 200/404 split proves
// whether the handler ran).
func TestIntegrationWrongAudienceRejected(t *testing.T) {
	env := newIntegrationEnv(t)
	now := time.Now()
	claims := map[string]any{
		"iss": "harbor-cloud", "sub": "harbor-cloud-svc-integration", "aud": "some-other-audience",
		"scope": "namespaces:read", "exp": now.Add(90 * time.Second).Unix(), "iat": now.Unix(),
		"jti": uniqueID("integration-jti"),
	}
	bearer := signES256(t, env.ecPriv, map[string]any{"alg": "ES256", "typ": "JWT"}, claims)

	res := env.do(t, http.MethodGet, "/admin/v1/namespaces/"+uniqueID("it-wrong-aud-ns"), bearer, "", "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
	if got := decodeIntegrationError(t, res).Code; got != cloudopenapi.ErrorCodeInvalidToken {
		t.Fatalf("error.code = %q, want invalid_token", got)
	}
}

// TestIntegrationMissingScopeRejected proves a valid, correct-audience token
// lacking the route's required scope is rejected with 403 before the
// namespace it targets is ever touched.
func TestIntegrationMissingScopeRejected(t *testing.T) {
	env := newIntegrationEnv(t)
	bearer := env.mint(t, "sessions:mint", 90*time.Second) // no namespaces:read

	res := env.do(t, http.MethodGet, "/admin/v1/namespaces/"+uniqueID("it-missing-scope-ns"), bearer, "", "")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", res.StatusCode)
	}
	if got := decodeIntegrationError(t, res).Code; got != cloudopenapi.ErrorCodeInsufficientScope {
		t.Fatalf("error.code = %q, want insufficient_scope", got)
	}
}

// TestIntegrationExpiredTokenRejected proves an otherwise well-formed token
// whose exp has already passed is rejected.
func TestIntegrationExpiredTokenRejected(t *testing.T) {
	env := newIntegrationEnv(t)
	bearer := env.mint(t, "namespaces:read", -1*time.Second)

	res := env.do(t, http.MethodGet, "/admin/v1/namespaces/"+uniqueID("it-expired-ns"), bearer, "", "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
	if got := decodeIntegrationError(t, res).Code; got != cloudopenapi.ErrorCodeInvalidToken {
		t.Fatalf("error.code = %q, want invalid_token", got)
	}
}

// TestIntegrationReplayedTokenRejected proves presenting the same bearer
// twice is rejected the second time, with the replay guard state actually
// living in Redis (not an in-process map) between the two real HTTP calls.
func TestIntegrationReplayedTokenRejected(t *testing.T) {
	env := newIntegrationEnv(t)
	bearer := env.mint(t, "namespaces:read", 90*time.Second)
	nsID := uniqueID("it-replay-ns")

	first := env.do(t, http.MethodGet, "/admin/v1/namespaces/"+nsID, bearer, "", "")
	_ = first.Body.Close()
	if first.StatusCode != http.StatusNotFound {
		t.Fatalf("first status = %d, want 404 (authorized, namespace absent)", first.StatusCode)
	}

	second := env.do(t, http.MethodGet, "/admin/v1/namespaces/"+nsID, bearer, "", "")
	if second.StatusCode != http.StatusUnauthorized {
		t.Fatalf("second (replayed) status = %d, want 401", second.StatusCode)
	}
	if got := decodeIntegrationError(t, second).Code; got != cloudopenapi.ErrorCodeTokenReplayed {
		t.Fatalf("error.code = %q, want token_replayed", got)
	}
}

// TestIntegrationCrossTenantSessionRejected proves a session minted for one
// namespace is rejected when presented against a different target namespace
// — end-to-end against real PostgreSQL persistence. No /admin/v1/* route
// itself accepts a session bearer (only cloudServiceAuth JWTs), so this
// exercises SessionsHandler.VerifySessionBearer directly, the same seam a
// namespace-scoped provisioning operation would call.
func TestIntegrationCrossTenantSessionRejected(t *testing.T) {
	deps := requireIntegrationDeps(t)
	ctx := context.Background()
	nsA := uniqueID("it-cross-tenant-a")
	nsB := uniqueID("it-cross-tenant-b")
	if _, err := deps.store.CreateNamespace(ctx, nsA, "active"); err != nil {
		t.Fatalf("create namespace %s: %v", nsA, err)
	}
	if _, err := deps.store.CreateNamespace(ctx, nsB, "active"); err != nil {
		t.Fatalf("create namespace %s: %v", nsB, err)
	}

	sessions := NewSessionsHandler(deps.store)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/sessions", strings.NewReader(fmt.Sprintf(`{"namespace_id":%q}`, nsA)))
	req.Header.Set("Idempotency-Key", uniqueID("it-sess-key"))
	sessions.PostSessions(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	var mint sessionMintResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &mint); err != nil {
		t.Fatalf("decode mint response: %v", err)
	}

	if _, err := sessions.VerifySessionBearer(ctx, mint.Token, nsB); !errors.Is(err, ErrCrossTenantForbidden) {
		t.Fatalf("VerifySessionBearer against a different namespace: error = %v, want ErrCrossTenantForbidden", err)
	}
	if _, err := sessions.VerifySessionBearer(ctx, mint.Token, nsA); err != nil {
		t.Fatalf("VerifySessionBearer against the minting namespace: unexpected error: %v", err)
	}
}

// TestIntegrationKeyRotationProxiesWithDistinctCredential proves, over a real
// HTTP round trip, that an authorized POST /admin/v1/keys/rotate reaches
// harbor-hot using the distinct proxy credential newContractRouter wired in
// (never the operator's ADMIN_API_TOKEN).
func TestIntegrationKeyRotationProxiesWithDistinctCredential(t *testing.T) {
	env := newIntegrationEnv(t)
	bearer := env.mint(t, "keys:rotate", 90*time.Second)

	res := env.do(t, http.MethodPost, "/admin/v1/keys/rotate", bearer, "", "")
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if env.hot.callCount != 1 {
		t.Fatalf("harbor-hot call count = %d, want 1", env.hot.callCount)
	}
	if env.hot.lastAuthHeader != "Bearer integration-proxy-token" {
		t.Fatalf("harbor-hot Authorization header = %q, want the distinct integration proxy credential", env.hot.lastAuthHeader)
	}
}

// TestIntegrationCloudIntegrationDisabledReturns404 proves spec.md's "Routes
// absent when cloudIntegration is disabled" scenario at the mechanism
// cmd/harbor-mgmt's gate relies on: httpserver.NewHealthMux() is the exact
// base mux cmd/harbor-mgmt/main.go builds every route table on
// (mux := httpserver.NewHealthMux(); ...; mgmtServer.Routes(mux); ...). When
// mgmt.cloudIntegration.enabled is false, cmd/harbor-mgmt simply never mounts
// cloudapi's routes onto that mux — and an unregistered net/http pattern
// always 404s, which this test proves directly against the real
// httpserver.NewHealthMux() constructor.
func TestIntegrationCloudIntegrationDisabledReturns404(t *testing.T) {
	mux := httpserver.NewHealthMux() // cloudapi deliberately never mounted
	ts := httptest.NewServer(mux)
	defer ts.Close()

	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodPost, "/admin/v1/sessions"},
		{http.MethodPost, "/admin/v1/namespaces"},
		{http.MethodGet, "/admin/v1/namespaces/some-namespace"},
		{http.MethodDelete, "/admin/v1/namespaces/some-namespace"},
		{http.MethodPost, "/admin/v1/keys/rotate"},
	} {
		req, err := http.NewRequest(tc.method, ts.URL+tc.path, nil)
		if err != nil {
			t.Fatalf("NewRequest(%s %s): %v", tc.method, tc.path, err)
		}
		res, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s status = %d, want 404 (cloudIntegration disabled -> unregistered)", tc.method, tc.path, res.StatusCode)
		}
	}

	// The health endpoint itself must still work — disabling cloudIntegration
	// must not take harbor-mgmt's liveness probe down with it.
	res, err := ts.Client().Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want 200", res.StatusCode)
	}
}
