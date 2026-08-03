package cloudapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/oidcapi"
)

// recordingHotServer is a stand-in for harbor-hot's POST /admin/keys/rotate:
// it records the Authorization header and body of the last request it
// received and returns a canned status/body, without any real rotation
// logic — these tests exercise the proxy hop, not harbor-hot's rotation
// state machine (which is already tested in internal/oidcapi).
type recordingHotServer struct {
	*httptest.Server
	lastAuthHeader string
	lastBody       []byte
	callCount      int
	status         int
	respBody       []byte
}

func newRecordingHotServer(t *testing.T) *recordingHotServer {
	t.Helper()
	rs := &recordingHotServer{
		status:   http.StatusOK,
		respBody: []byte(`{"new_kid":"kid-2","promoted_at":"2026-01-01T12:00:00Z"}`),
	}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/admin/keys/rotate" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		rs.callCount++
		rs.lastAuthHeader = r.Header.Get("Authorization")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		rs.lastBody = body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rs.status)
		_, _ = w.Write(rs.respBody)
	}))
	t.Cleanup(rs.Close)
	return rs
}

// newKeysTestHandler builds a KeysHandler wired to hot (a recordingHotServer
// standing in for harbor-hot) using proxyToken as MGMT_HOT_PROXY_TOKEN.
func newKeysTestHandler(t *testing.T, env *testEnv, hot *recordingHotServer, proxyToken string) *KeysHandler {
	t.Helper()
	return NewKeysHandler(env.verifier, hot.URL, proxyToken, hot.Client())
}

func rotateReq(t *testing.T, bearer string, body []byte) *http.Request {
	t.Helper()
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(http.MethodPost, "/admin/v1/keys/rotate", nil)
	} else {
		r = httptest.NewRequest(http.MethodPost, "/admin/v1/keys/rotate", bytes.NewReader(body))
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	return r
}

func decodeKeysError(t *testing.T, rec *httptest.ResponseRecorder) errorBody {
	t.Helper()
	var e errorBody
	if err := json.NewDecoder(rec.Body).Decode(&e); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	return e
}

// --- scope enforcement ---

// TestKeysHandler_RequiresScope verifies that a valid bearer lacking the
// keys:rotate scope is rejected with 403 insufficient_scope and harbor-hot is
// never called.
func TestKeysHandler_RequiresScope(t *testing.T) {
	env := newTestEnv(t)
	hot := newRecordingHotServer(t)
	h := newKeysTestHandler(t, env, hot, "cloud-proxy-token")

	claims := env.validClaims() // scope: "sessions:mint namespaces:read" — no keys:rotate
	token := env.sign(t, claims)

	rec := httptest.NewRecorder()
	h.PostKeysRotate(rec, rotateReq(t, token, nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	e := decodeKeysError(t, rec)
	if e.Code != "insufficient_scope" {
		t.Fatalf("error.code = %q, want insufficient_scope", e.Code)
	}
	if hot.callCount != 0 {
		t.Fatalf("harbor-hot call count = %d, want 0 (scope check must short-circuit before proxying)", hot.callCount)
	}
}

// TestKeysHandler_ScopeGrantedAmongOthers verifies that keys:rotate need not
// be the only granted scope.
func TestKeysHandler_ScopeGrantedAmongOthers(t *testing.T) {
	env := newTestEnv(t)
	hot := newRecordingHotServer(t)
	h := newKeysTestHandler(t, env, hot, "cloud-proxy-token")

	claims := env.validClaims()
	claims["scope"] = "namespaces:read keys:rotate"
	token := env.sign(t, claims)

	rec := httptest.NewRecorder()
	h.PostKeysRotate(rec, rotateReq(t, token, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if hot.callCount != 1 {
		t.Fatalf("harbor-hot call count = %d, want 1", hot.callCount)
	}
}

// --- bearer verification ---

// TestKeysHandler_MissingBearer verifies that an absent Authorization header
// is rejected with 401 invalid_token.
func TestKeysHandler_MissingBearer(t *testing.T) {
	env := newTestEnv(t)
	hot := newRecordingHotServer(t)
	h := newKeysTestHandler(t, env, hot, "cloud-proxy-token")

	rec := httptest.NewRecorder()
	h.PostKeysRotate(rec, rotateReq(t, "", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	e := decodeKeysError(t, rec)
	if e.Code != "invalid_token" {
		t.Fatalf("error.code = %q, want invalid_token", e.Code)
	}
	if hot.callCount != 0 {
		t.Fatalf("harbor-hot call count = %d, want 0", hot.callCount)
	}
}

// TestKeysHandler_InvalidBearer verifies that a malformed/unsigned bearer is
// rejected with 401 invalid_token.
func TestKeysHandler_InvalidBearer(t *testing.T) {
	env := newTestEnv(t)
	hot := newRecordingHotServer(t)
	h := newKeysTestHandler(t, env, hot, "cloud-proxy-token")

	rec := httptest.NewRecorder()
	h.PostKeysRotate(rec, rotateReq(t, "not-a-jwt", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if hot.callCount != 0 {
		t.Fatalf("harbor-hot call count = %d, want 0", hot.callCount)
	}
}

// TestKeysHandler_ReplayedBearer verifies that presenting the same bearer
// token twice is rejected the second time with 401 token_replayed.
func TestKeysHandler_ReplayedBearer(t *testing.T) {
	env := newTestEnv(t)
	hot := newRecordingHotServer(t)
	h := newKeysTestHandler(t, env, hot, "cloud-proxy-token")

	claims := env.validClaims()
	claims["scope"] = "keys:rotate"
	token := env.sign(t, claims)

	rec1 := httptest.NewRecorder()
	h.PostKeysRotate(rec1, rotateReq(t, token, nil))
	if rec1.Code != http.StatusOK {
		t.Fatalf("first call status = %d, want 200", rec1.Code)
	}

	rec2 := httptest.NewRecorder()
	h.PostKeysRotate(rec2, rotateReq(t, token, nil))
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("replayed call status = %d, want 401", rec2.Code)
	}
	e := decodeKeysError(t, rec2)
	if e.Code != "token_replayed" {
		t.Fatalf("error.code = %q, want token_replayed", e.Code)
	}
	if hot.callCount != 1 {
		t.Fatalf("harbor-hot call count = %d, want 1 (replay must not reach harbor-hot)", hot.callCount)
	}
}

// --- request body handling ---

// TestKeysHandler_MalformedBody verifies that a non-JSON body is rejected
// with 400 invalid_request before ever reaching harbor-hot.
func TestKeysHandler_MalformedBody(t *testing.T) {
	env := newTestEnv(t)
	hot := newRecordingHotServer(t)
	h := newKeysTestHandler(t, env, hot, "cloud-proxy-token")

	claims := env.validClaims()
	claims["scope"] = "keys:rotate"
	token := env.sign(t, claims)

	rec := httptest.NewRecorder()
	h.PostKeysRotate(rec, rotateReq(t, token, []byte("{not json")))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if hot.callCount != 0 {
		t.Fatalf("harbor-hot call count = %d, want 0", hot.callCount)
	}
}

// TestKeysHandler_EmergencyBodyForwarded verifies that a well-formed
// {"emergency": true} body is forwarded to harbor-hot byte-for-byte.
func TestKeysHandler_EmergencyBodyForwarded(t *testing.T) {
	env := newTestEnv(t)
	hot := newRecordingHotServer(t)
	h := newKeysTestHandler(t, env, hot, "cloud-proxy-token")

	claims := env.validClaims()
	claims["scope"] = "keys:rotate"
	token := env.sign(t, claims)

	body := []byte(`{"emergency":true}`)
	rec := httptest.NewRecorder()
	h.PostKeysRotate(rec, rotateReq(t, token, body))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if string(hot.lastBody) != string(body) {
		t.Fatalf("harbor-hot received body = %q, want %q", hot.lastBody, body)
	}
}

// --- proxy credential + response relay ---

// TestKeysHandler_ProxiesWithCloudProxyCredential verifies that harbor-hot
// receives MGMT_HOT_PROXY_TOKEN — never any other credential — and that
// harbor-hot's response is relayed verbatim.
func TestKeysHandler_ProxiesWithCloudProxyCredential(t *testing.T) {
	env := newTestEnv(t)
	hot := newRecordingHotServer(t)
	const proxyToken = "the-mgmt-hot-proxy-token"
	h := newKeysTestHandler(t, env, hot, proxyToken)

	claims := env.validClaims()
	claims["scope"] = "keys:rotate"
	token := env.sign(t, claims)

	rec := httptest.NewRecorder()
	h.PostKeysRotate(rec, rotateReq(t, token, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if hot.lastAuthHeader != "Bearer "+proxyToken {
		t.Fatalf("harbor-hot Authorization header = %q, want %q", hot.lastAuthHeader, "Bearer "+proxyToken)
	}
	if rec.Body.String() != string(hot.respBody) {
		t.Fatalf("response body = %q, want harbor-hot's response %q relayed verbatim", rec.Body.String(), hot.respBody)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}

// TestKeysHandler_RelaysHarborHotErrorStatus verifies that a non-2xx status
// harbor-hot itself returns (e.g. its own rotation failure) is relayed
// verbatim rather than mapped to a synthesized cloudapi error.
func TestKeysHandler_RelaysHarborHotErrorStatus(t *testing.T) {
	env := newTestEnv(t)
	hot := newRecordingHotServer(t)
	hot.status = http.StatusInternalServerError
	hot.respBody = []byte(`{"code":"rotation_failed","message":"signing key rotation failed"}`)
	h := newKeysTestHandler(t, env, hot, "cloud-proxy-token")

	claims := env.validClaims()
	claims["scope"] = "keys:rotate"
	token := env.sign(t, claims)

	rec := httptest.NewRecorder()
	h.PostKeysRotate(rec, rotateReq(t, token, nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (relayed from harbor-hot)", rec.Code)
	}
	if rec.Body.String() != string(hot.respBody) {
		t.Fatalf("response body = %q, want harbor-hot's error body relayed verbatim", rec.Body.String())
	}
}

// TestKeysHandler_ProxyUnreachable verifies that a transport-level failure
// reaching harbor-hot (not a response harbor-hot itself sent) is mapped to
// 500 server_error.
func TestKeysHandler_ProxyUnreachable(t *testing.T) {
	env := newTestEnv(t)
	// A closed server: connections to its former address are refused.
	hot := newRecordingHotServer(t)
	unreachableURL := hot.URL
	hot.Close()

	h := NewKeysHandler(env.verifier, unreachableURL, "cloud-proxy-token", &http.Client{Timeout: 2 * time.Second})

	claims := env.validClaims()
	claims["scope"] = "keys:rotate"
	token := env.sign(t, claims)

	rec := httptest.NewRecorder()
	h.PostKeysRotate(rec, rotateReq(t, token, nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	e := decodeKeysError(t, rec)
	if e.Code != "server_error" {
		t.Fatalf("error.code = %q, want server_error", e.Code)
	}
}

// --- constructor guards ---

// TestNewKeysHandler_PanicsOnMissingDependencies verifies the fail-fast boot
// contract: a nil verifier or an empty hotBaseURL/proxyToken panics rather
// than silently building a handler that could accept requests without
// actually being able to authenticate or proxy them.
func TestNewKeysHandler_PanicsOnMissingDependencies(t *testing.T) {
	env := newTestEnv(t)
	hot := newRecordingHotServer(t)

	cases := []struct {
		name string
		fn   func()
	}{
		{"nil verifier", func() { NewKeysHandler(nil, hot.URL, "tok", nil) }},
		{"empty hotBaseURL", func() { NewKeysHandler(env.verifier, "", "tok", nil) }},
		{"empty proxyToken", func() { NewKeysHandler(env.verifier, hot.URL, "", nil) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("expected a panic")
				}
			}()
			tc.fn()
		})
	}
}

// --- cross-package: harbor-hot's own AdminAuthMiddleware attributes the
// proxy call to credential=cloud-proxy, distinct from a direct operator
// call (credential=operator) ---

// TestKeysHandler_HarborHotAuditDistinguishesCredential wires a fake
// harbor-hot backend behind the REAL oidcapi.AdminAuthMiddleware (configured
// exactly as cmd/harbor-hot/main.go wires it: ADMIN_API_TOKEN labeled
// "operator", MGMT_HOT_PROXY_TOKEN labeled "cloud-proxy") and verifies that:
//   - a call proxied through KeysHandler (using MGMT_HOT_PROXY_TOKEN) is
//     logged by harbor-hot's own middleware as credential=cloud-proxy
//   - a direct call presenting ADMIN_API_TOKEN is logged as credential=operator
//
// This is the guarantee design.md §5 relies on: leaking one credential is
// distinguishable from leaking the other in harbor-hot's own audit log.
func TestKeysHandler_HarborHotAuditDistinguishesCredential(t *testing.T) {
	const operatorToken = "operator-admin-token-value"
	const cloudProxyToken = "cloud-proxy-admin-token-value"

	var logBuf bytes.Buffer
	adminMW := oidcapi.AdminAuthMiddleware(oidcapi.AdminAuthConfig{
		Credentials: []oidcapi.AdminCredential{
			{Label: "operator", Token: operatorToken},
			{Label: "cloud-proxy", Token: cloudProxyToken},
		},
		Logger: slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})

	rotateHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"new_kid":"kid-2","promoted_at":"2026-01-01T12:00:00Z"}`))
	})
	hotServer := httptest.NewServer(adminMW(rotateHandler))
	t.Cleanup(hotServer.Close)

	// Proxied call via KeysHandler, using MGMT_HOT_PROXY_TOKEN.
	env := newTestEnv(t)
	h := NewKeysHandler(env.verifier, hotServer.URL, cloudProxyToken, hotServer.Client())
	claims := env.validClaims()
	claims["scope"] = "keys:rotate"
	token := env.sign(t, claims)

	logBuf.Reset()
	rec := httptest.NewRecorder()
	h.PostKeysRotate(rec, rotateReq(t, token, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("proxied call status = %d, want 200", rec.Code)
	}
	if !strings.Contains(logBuf.String(), "credential=cloud-proxy") {
		t.Fatalf("harbor-hot audit log for the proxied call = %q, want it to contain credential=cloud-proxy", logBuf.String())
	}
	if strings.Contains(logBuf.String(), "credential=operator") {
		t.Fatalf("harbor-hot audit log for the proxied call = %q, must NOT contain credential=operator", logBuf.String())
	}

	// Direct call presenting the operator credential straight to harbor-hot.
	logBuf.Reset()
	req, err := http.NewRequest(http.MethodPost, hotServer.URL+"/admin/keys/rotate", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+operatorToken)
	res, err := hotServer.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("direct operator call status = %d, want 200", res.StatusCode)
	}
	if !strings.Contains(logBuf.String(), "credential=operator") {
		t.Fatalf("harbor-hot audit log for the direct operator call = %q, want it to contain credential=operator", logBuf.String())
	}
	if strings.Contains(logBuf.String(), "credential=cloud-proxy") {
		t.Fatalf("harbor-hot audit log for the direct operator call = %q, must NOT contain credential=cloud-proxy", logBuf.String())
	}
}
