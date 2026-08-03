// contract_test.go builds a real, end-to-end /admin/v1/* HTTP surface out of
// the production pieces this package already ships — Server, SessionsHandler,
// KeysHandler, and ServiceAuthVerifier — wired together exactly the way
// design.md describes cmd/harbor-mgmt will wire them (§1 "mounted on the
// existing health mux", §2 "harbor-mgmt verifies against a configured
// trust-anchor public key"). It is deliberately test-only glue: no production
// file gains a new export, and nothing here is reachable from a shipped
// binary (internal/arch's TestProductionCompositionRootsContainNoScaffolds
// only inspects cmd/*'s non-test sources).
//
// Every route's required scope is read from the context value the
// generated cloudopenapi.ServerInterfaceWrapper already attaches
// (CloudServiceAuthScopes) — the same mechanism a production middleware would
// use — so adding a sixth operation to api/openapi/harbor-cloud.yaml would
// require no change here.
//
// This router is shared by contract_test.go (fixture-driven, in-process) and
// integration_test.go (-tags=integration, real Postgres/Redis, real HTTP via
// httptest.NewServer).
package cloudapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/harbor-auth/harbor/internal/clients"
	cloudopenapi "github.com/harbor-auth/harbor/internal/gen/openapi/cloud"
	"github.com/harbor-auth/harbor/internal/oidcapi"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

// contractAdapter implements cloudopenapi.ServerInterface by delegating to the
// real handlers. Namespace operations already match the generated interface
// signature directly (namespaces.go); sessions and key rotation predate the
// generated ServerInterface and use their own narrower method shapes
// (SessionsHandler.PostSessions, KeysHandler.PostKeysRotate) — this adapter is
// the seam that reconciles the two without changing either production file.
type contractAdapter struct {
	*Server
	sessions *SessionsHandler
	keys     *KeysHandler
}

var _ cloudopenapi.ServerInterface = (*contractAdapter)(nil)

func (a *contractAdapter) PostAdminV1Sessions(w http.ResponseWriter, r *http.Request, _ cloudopenapi.PostAdminV1SessionsParams) {
	a.sessions.PostSessions(w, r)
}

func (a *contractAdapter) PostAdminV1KeysRotate(w http.ResponseWriter, r *http.Request) {
	a.keys.PostKeysRotate(w, r)
}

// adminV1KeysRotatePath is the one route KeysHandler already authenticates
// and scope-checks itself (keys.go: PostKeysRotate calls h.authorize before
// doing anything else). requireServiceAuth must not also verify this route —
// a second Verify call on the same bearer would see its jti as already
// claimed and reject a legitimate first-time caller with token_replayed.
const adminV1KeysRotatePath = "/admin/v1/keys/rotate"

// requireServiceAuth is the generic cloudServiceAuth middleware every other
// /admin/v1/* route relies on (namespaces.go and sessions.go hold no auth
// state of their own — see namespaces.go's Server doc comment). It reads the
// operation's required scope from the context value the generated
// ServerInterfaceWrapper attaches before invoking the handler
// (cloudopenapi.CloudServiceAuthScopes), so it generalizes to every route
// without a hand-maintained path->scope table.
func requireServiceAuth(verifier *ServiceAuthVerifier) cloudopenapi.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == adminV1KeysRotatePath {
				next.ServeHTTP(w, r)
				return
			}

			bearer := extractBearerToken(r)
			if bearer == "" {
				writeVerifyError(w, ErrInvalidToken)
				return
			}
			route := r.Method + " " + r.URL.Path
			claims, err := verifier.Verify(WithRoute(r.Context(), route), bearer)
			if err != nil {
				writeVerifyError(w, err)
				return
			}
			if required, ok := r.Context().Value(cloudopenapi.CloudServiceAuthScopes).([]string); ok {
				for _, scope := range required {
					if !claims.HasScope(scope) {
						writeCloudAPIError(w, http.StatusForbidden, "insufficient_scope", "the "+scope+" scope is required")
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// newContractRouter assembles the real /admin/v1/* http.Handler over the
// given store and verifier — the same composition every scenario in this
// package's tests (fixture-driven and integration) exercises requests
// through.
func newContractRouter(store *Store, verifier *ServiceAuthVerifier, hotBaseURL, proxyToken string, hotClient *http.Client) http.Handler {
	adapter := &contractAdapter{
		Server:   NewServer(store),
		sessions: NewSessionsHandler(store),
		keys:     NewKeysHandler(verifier, hotBaseURL, proxyToken, hotClient),
	}
	return cloudopenapi.HandlerWithOptions(adapter, cloudopenapi.StdHTTPServerOptions{
		Middlewares: []cloudopenapi.MiddlewareFunc{requireServiceAuth(verifier)},
	})
}

// --- fixture format --------------------------------------------------------

// contractFixture is one request/response scenario from spec.md, expressed as
// one or more sequential HTTP steps against the router built above (a create
// followed by its idempotent retry, for instance, is two steps in one
// fixture). Fixtures live under testdata/contract/ as one JSON file per
// scenario.
type contractFixture struct {
	// Name is a short, stable scenario identifier (also the JSON filename
	// stem), used in test names and failure output.
	Name string `json:"name"`
	// SpecScenario names the exact "#### Scenario: ..." heading in spec.md
	// this fixture proves, so drift between the two is easy to audit by hand.
	SpecScenario string         `json:"spec_scenario"`
	Steps        []contractStep `json:"steps"`
}

type contractStep struct {
	Method string `json:"method"`
	Path   string `json:"path"`

	// Auth selects how the Authorization header is built for this step:
	//   "valid"                  - mint a fresh, well-formed token granting Scope
	//   "none"                   - send no Authorization header at all
	//   "wrong_audience"         - valid signature, aud != harbor-mgmt-cloudapi
	//   "no_scope_claim"         - valid signature, empty scope claim
	//   "insufficient_scope"     - valid token granting Scope, which does NOT
	//                              cover the route's required scope
	//   "expired"                - valid signature, exp already in the past
	//   "unconfigured_trust_anchor" - run against a verifier with no configured
	//                              trust anchor (every request fails closed)
	//   "reused_from_step"       - replay the exact bearer minted for an earlier
	//                              step, identified by ReuseFromStep (1-indexed)
	//   "raw"                    - send RawBearer verbatim (e.g. a static
	//                              operator/initial-access token, never a JWT)
	Auth string `json:"auth"`
	// Scope is the space-delimited scope claim granted when Auth is "valid",
	// "expired", or "insufficient_scope".
	Scope string `json:"scope,omitempty"`
	// ReuseFromStep is the 1-indexed step whose minted bearer this step
	// replays, used with Auth "reused_from_step".
	ReuseFromStep int `json:"reuse_from_step,omitempty"`
	// RawBearer is sent verbatim as the bearer credential when Auth is "raw" —
	// used to prove a non-JWT static credential (ADMIN_API_TOKEN, an RFC 7591
	// initial-access token) is never accepted on this surface.
	RawBearer string `json:"raw_bearer,omitempty"`

	// IdempotencyKey, when non-empty, is sent as the Idempotency-Key header.
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	// RequestBody is marshaled verbatim as the JSON request body. nil means
	// no body at all.
	RequestBody json.RawMessage `json:"request_body,omitempty"`

	// WantStatus is the required HTTP status code.
	WantStatus int `json:"want_status"`
	// WantErrorCode, when non-empty, is the required Error.code of the
	// response body (api/openapi/harbor-cloud.yaml `Error` schema).
	WantErrorCode string `json:"want_error_code,omitempty"`
	// WantBodyContains, when non-empty, is a set of top-level JSON fields the
	// response body must contain with exactly these values.
	WantBodyContains map[string]any `json:"want_body_contains,omitempty"`
	// WantBodyNonEmptyFields, when non-empty, names top-level JSON fields that
	// must be present with a non-empty value (e.g. a randomly-generated
	// session_id/token), without pinning the exact value.
	WantBodyNonEmptyFields []string `json:"want_body_nonempty_fields,omitempty"`
	// WantSameBodyAsStep, when set (1-indexed), asserts this step's response
	// body is byte-identical to an earlier step's — the idempotent-replay
	// contract.
	WantSameBodyAsStep int `json:"want_same_body_as_step,omitempty"`
}

// loadContractFixtures reads every *.json file directly under dir (no
// subdirectory recursion) as a contractFixture.
func loadContractFixtures(t *testing.T, dir string) []contractFixture {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read fixture dir %s: %v", dir, err)
	}
	var fixtures []contractFixture
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read fixture %s: %v", e.Name(), err)
		}
		var f contractFixture
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatalf("decode fixture %s: %v", e.Name(), err)
		}
		if f.Name == "" {
			t.Fatalf("fixture %s: missing \"name\"", e.Name())
		}
		fixtures = append(fixtures, f)
	}
	if len(fixtures) == 0 {
		t.Fatalf("no fixtures found under %s", dir)
	}
	return fixtures
}

// --- fixture runner ---------------------------------------------------------

// contractEnv bundles the pieces a fixture-driven run needs: the real router
// (backed by an in-memory store and a miniredis replay guard) plus, lazily, a
// second router whose verifier has no configured trust anchor — for the
// "unconfigured_trust_anchor" auth mode, which must fail closed independent
// of whatever bearer is presented.
type contractEnv struct {
	router  http.Handler
	ecPriv  *ecdsa.PrivateKey
	now     time.Time
	jtiSeq  int
	q       *memQuerier
	unconfR http.Handler
}

func newContractEnv(t *testing.T) *contractEnv {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() }) //nolint:errcheck // test cleanup

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	verifier, err := NewServiceAuthVerifier(ServiceAuthVerifierConfig{
		PublicKeyPEM: pemEncodePublicKey(t, &priv.PublicKey),
		ReplayGuard:  NewRedisReplayGuard(redisClient),
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewServiceAuthVerifier: %v", err)
	}

	q := newMemQuerier()
	store := NewStore(q)
	hot := newRecordingHotServer(t)

	env := &contractEnv{
		router: newContractRouter(store, verifier, hot.URL, "contract-proxy-token", hot.Client()),
		ecPriv: priv,
		now:    now,
		q:      q,
	}

	unconfVerifier, err := NewServiceAuthVerifier(ServiceAuthVerifierConfig{
		ReplayGuard: NewRedisReplayGuard(redisClient),
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewServiceAuthVerifier (unconfigured): %v", err)
	}
	env.unconfR = newContractRouter(NewStore(newMemQuerier()), unconfVerifier, hot.URL, "contract-proxy-token", hot.Client())

	return env
}

// nextJTI returns a fresh, never-repeating jti so successive "valid" mints in
// the same fixture never collide with the replay guard.
func (e *contractEnv) nextJTI() string {
	e.jtiSeq++
	return fmt.Sprintf("contract-jti-%d", e.jtiSeq)
}

// mintFor mints a bearer token for auth mode/scope, returning "" for auth
// modes that send no Authorization header at all ("none").
func (e *contractEnv) mintFor(t *testing.T, auth, scope string) string {
	t.Helper()
	claims := map[string]any{
		"iss":   "harbor-cloud",
		"sub":   "harbor-cloud-svc-contract",
		"aud":   ExpectedAudience,
		"scope": scope,
		"exp":   e.now.Add(90 * time.Second).Unix(),
		"iat":   e.now.Unix(),
		"jti":   e.nextJTI(),
	}
	switch auth {
	case "none":
		return ""
	case "valid", "insufficient_scope", "unconfigured_trust_anchor":
		// unconfigured_trust_anchor uses an otherwise well-formed token — the
		// rejection must come from the missing trust anchor, not the token.
	case "wrong_audience":
		claims["aud"] = "some-other-service"
	case "no_scope_claim":
		claims["scope"] = ""
	case "expired":
		claims["exp"] = e.now.Add(-1 * time.Second).Unix()
	default:
		t.Fatalf("unknown auth mode %q", auth)
	}
	return signES256(t, e.ecPriv, map[string]any{"alg": "ES256", "typ": "JWT"}, claims)
}

// runFixture replays every step of f against env in order, resolving each
// step's Auth mode to a concrete bearer and checking every declared
// expectation.
func runContractFixture(t *testing.T, env *contractEnv, f contractFixture) {
	t.Helper()
	bearers := make([]string, len(f.Steps))
	bodies := make([][]byte, len(f.Steps))

	for i, step := range f.Steps {
		router := env.router
		var bearer string
		switch step.Auth {
		case "reused_from_step":
			if step.ReuseFromStep < 1 || step.ReuseFromStep > len(bearers) {
				t.Fatalf("step %d: reuse_from_step %d out of range", i+1, step.ReuseFromStep)
			}
			bearer = bearers[step.ReuseFromStep-1]
		case "unconfigured_trust_anchor":
			router = env.unconfR
			bearer = env.mintFor(t, step.Auth, step.Scope)
		case "raw":
			bearer = step.RawBearer
		default:
			bearer = env.mintFor(t, step.Auth, step.Scope)
		}
		bearers[i] = bearer

		var bodyReader *bytes.Reader
		if len(step.RequestBody) > 0 {
			bodyReader = bytes.NewReader(step.RequestBody)
		} else {
			bodyReader = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(step.Method, step.Path, bodyReader)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if step.IdempotencyKey != "" {
			req.Header.Set("Idempotency-Key", step.IdempotencyKey)
		}
		if len(step.RequestBody) > 0 {
			req.Header.Set("Content-Type", "application/json")
		}

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		bodies[i] = rec.Body.Bytes()

		if rec.Code != step.WantStatus {
			t.Fatalf("fixture %q step %d (%s %s, auth=%s): status = %d, want %d; body = %s",
				f.Name, i+1, step.Method, step.Path, step.Auth, rec.Code, step.WantStatus, rec.Body.String())
		}

		if step.WantErrorCode != "" {
			var errBody cloudopenapi.Error
			if err := json.Unmarshal(bodies[i], &errBody); err != nil {
				t.Fatalf("fixture %q step %d: decode error envelope: %v; body = %s", f.Name, i+1, err, bodies[i])
			}
			if string(errBody.Code) != step.WantErrorCode {
				t.Fatalf("fixture %q step %d: error.code = %q, want %q", f.Name, i+1, errBody.Code, step.WantErrorCode)
			}
			if !validErrorCode(errBody.Code) {
				t.Fatalf("fixture %q step %d: error.code %q is not in api/openapi/harbor-cloud.yaml's Error.code enum", f.Name, i+1, errBody.Code)
			}
		}

		if len(step.WantBodyContains) > 0 {
			var got map[string]any
			if err := json.Unmarshal(bodies[i], &got); err != nil {
				t.Fatalf("fixture %q step %d: decode response body: %v; body = %s", f.Name, i+1, err, bodies[i])
			}
			for field, want := range step.WantBodyContains {
				if gotVal, ok := got[field]; !ok || !reflect.DeepEqual(gotVal, want) {
					t.Fatalf("fixture %q step %d: body field %q = %#v, want %#v (body = %s)", f.Name, i+1, field, gotVal, want, bodies[i])
				}
			}
		}

		if len(step.WantBodyNonEmptyFields) > 0 {
			var got map[string]any
			if err := json.Unmarshal(bodies[i], &got); err != nil {
				t.Fatalf("fixture %q step %d: decode response body: %v; body = %s", f.Name, i+1, err, bodies[i])
			}
			for _, field := range step.WantBodyNonEmptyFields {
				val, ok := got[field]
				if !ok || val == nil || val == "" {
					t.Fatalf("fixture %q step %d: body field %q missing or empty (body = %s)", f.Name, i+1, field, bodies[i])
				}
			}
		}

		if step.WantSameBodyAsStep > 0 {
			if step.WantSameBodyAsStep > len(bodies) || bodies[step.WantSameBodyAsStep-1] == nil {
				t.Fatalf("fixture %q step %d: want_same_body_as_step %d has no recorded body yet", f.Name, i+1, step.WantSameBodyAsStep)
			}
			if string(bodies[i]) != string(bodies[step.WantSameBodyAsStep-1]) {
				t.Fatalf("fixture %q step %d: body != step %d's body:\n got:  %s\n want: %s",
					f.Name, i+1, step.WantSameBodyAsStep, bodies[i], bodies[step.WantSameBodyAsStep-1])
			}
		}
	}
}

// validErrorCode reports whether code is one of the values documented in
// api/openapi/harbor-cloud.yaml's Error.code enum (internal/gen/openapi/cloud
// mirrors these as untyped string constants, so this list is checked by hand
// against the generated ErrorCode* constants rather than reflection).
func validErrorCode(code cloudopenapi.ErrorCode) bool {
	switch code {
	case cloudopenapi.ErrorCodeInvalidRequest,
		cloudopenapi.ErrorCodeInvalidToken,
		cloudopenapi.ErrorCodeInsufficientScope,
		cloudopenapi.ErrorCodeTokenReplayed,
		cloudopenapi.ErrorCodeSessionExpired,
		cloudopenapi.ErrorCodeCrossTenantForbidden,
		cloudopenapi.ErrorCodeNamespaceAlreadyExists,
		cloudopenapi.ErrorCodeNamespaceNotFound,
		cloudopenapi.ErrorCodeIdempotencyKeyReused,
		cloudopenapi.ErrorCodeRateLimited:
		return true
	default:
		return false
	}
}

// TestContractFixtures drives every JSON fixture under testdata/contract/
// through the real router (contractAdapter + requireServiceAuth +
// Server/SessionsHandler/KeysHandler), proving handler behavior matches
// api/openapi/harbor-cloud.yaml and every scenario in spec.md — without
// importing any harbor-cloud code (fixtures are plain JSON; the only Go
// dependency is this repo's own generated cloudopenapi package).
func TestContractFixtures(t *testing.T) {
	fixtures := loadContractFixtures(t, filepath.Join("testdata", "contract"))
	for _, f := range fixtures {
		f := f
		t.Run(f.Name, func(t *testing.T) {
			env := newContractEnv(t)
			runContractFixture(t, env, f)
		})
	}
}

// TestContractAuditEventsEmitted proves spec.md's "Successful and rejected
// calls are both audited" scenario: every /admin/v1/* request — accepted or
// rejected — produces a PII-free audit line carrying the route template, the
// outcome, and (when known) the caller's service identity. This is not a
// JSON fixture because it asserts on the log side channel, not the HTTP
// response.
func TestContractAuditEventsEmitted(t *testing.T) {
	var logBuf bytes.Buffer
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() }) //nolint:errcheck // test cleanup

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	verifier, err := NewServiceAuthVerifier(ServiceAuthVerifierConfig{
		PublicKeyPEM: pemEncodePublicKey(t, &priv.PublicKey),
		ReplayGuard:  NewRedisReplayGuard(redisClient),
		Now:          func() time.Time { return now },
		Logger:       newTelemetryLoggerTo(&logBuf),
	})
	if err != nil {
		t.Fatalf("NewServiceAuthVerifier: %v", err)
	}
	hot := newRecordingHotServer(t)
	router := newContractRouter(NewStore(newMemQuerier()), verifier, hot.URL, "contract-proxy-token", hot.Client())

	claims := map[string]any{
		"iss": "harbor-cloud", "sub": "harbor-cloud-svc-audit", "aud": ExpectedAudience,
		"scope": "namespaces:read", "exp": now.Add(90 * time.Second).Unix(), "iat": now.Unix(), "jti": "audit-jti-ok",
	}
	token := signES256(t, priv, map[string]any{"alg": "ES256", "typ": "JWT"}, claims)

	accepted := httptest.NewRequest(http.MethodGet, "/admin/v1/namespaces/audit-check-ns", nil)
	accepted.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(httptest.NewRecorder(), accepted)

	rejected := httptest.NewRequest(http.MethodGet, "/admin/v1/namespaces/audit-check-ns", nil)
	rejected.Header.Set("Authorization", "Bearer "+token) // replay of the same token
	router.ServeHTTP(httptest.NewRecorder(), rejected)

	log := logBuf.String()
	for _, want := range []string{
		"result=accepted", "result=rejected",
		"caller=harbor-cloud-svc-audit",
		`path_template="GET /admin/v1/namespaces/audit-check-ns"`,
		"error_code=token_replayed",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("audit log missing %q; full log:\n%s", want, log)
		}
	}
	// PII-free: the bearer credential itself must never appear in the log.
	if strings.Contains(log, token[:20]) {
		t.Errorf("audit log leaks bearer token material:\n%s", log)
	}
}

// newTelemetryLoggerTo builds a *telemetry.Logger writing to w, for tests
// that need to inspect the audit log side channel.
func newTelemetryLoggerTo(w *bytes.Buffer) *telemetry.Logger {
	return telemetry.New(slog.New(slog.NewTextHandler(w, nil)))
}

// TestContractRateLimitFailsClosed proves spec.md's "Rate limit exceeded is
// rejected" scenario using the same Redis-backed limiter middleware
// internal/oidcapi already ships (clients.RateLimiter + RateLimitMiddleware)
// — cloudapi's own per-route rate limiting is wired by cmd/harbor-mgmt in a
// later task, but the limiter contract (429 rate_limited, fail-closed on a
// backend error) is identical and already proven here end-to-end.
func TestContractRateLimitFailsClosed(t *testing.T) {
	env := newContractEnv(t)
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() }) //nolint:errcheck // test cleanup

	limiter := clients.NewRedisRateLimiter(redisClient, clients.RateLimiterConfig{
		KeyPrefix: "ratelimit:contract-test:",
		Limit:     1,
		Window:    time.Minute,
	}, slog.Default())
	rateLimited := oidcapi.RateLimitMiddleware(oidcapi.RateLimitConfig{
		Limiter:           limiter,
		Endpoint:          telemetry.EndpointAdminRotate,
		Window:            time.Minute,
		FailClosedOnError: true,
	})(env.router)

	token := env.mintFor(t, "valid", "namespaces:read")
	get := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/namespaces/rate-check-ns", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		rateLimited.ServeHTTP(rec, req)
		return rec
	}

	first := get()
	if first.Code != http.StatusNotFound {
		t.Fatalf("first request status = %d, want 404 (auth accepted, namespace absent); body = %s", first.Code, first.Body.String())
	}

	second := get()
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429; body = %s", second.Code, second.Body.String())
	}
	var errBody cloudopenapi.Error
	if err := json.Unmarshal(second.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("decode 429 body: %v; body = %s", err, second.Body.String())
	}
	if errBody.Code != cloudopenapi.ErrorCodeRateLimited {
		t.Errorf("error.code = %q, want rate_limited", errBody.Code)
	}
}
