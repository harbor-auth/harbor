// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestLoginHandler returns a LoginHandler wired to a fake authorization
// endpoint and a fresh session store, matching how main.go wires it except
// for using httptest-friendly values.
func newTestLoginHandler() *LoginHandler {
	return &LoginHandler{
		AuthorizeURL: "https://idp.example.com/authorize",
		ClientID:     "configured-client-id",
		RedirectURI:  "https://rp.example.com/auth/callback",
		Sessions:     newSessionStore(),
	}
}

// authorizeRedirect drives h with req and returns the parsed Location header
// of the resulting redirect. It fails the test if the handler does not
// respond with a redirect to h.AuthorizeURL.
func authorizeRedirect(t *testing.T, h *LoginHandler, req *http.Request) url.Values {
	t.Helper()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("ServeHTTP: status = %d, want %d", rec.Code, http.StatusFound)
	}

	loc := rec.Header().Get("Location")
	prefix := h.AuthorizeURL + "?"
	if !strings.HasPrefix(loc, prefix) {
		t.Fatalf("Location = %q, want prefix %q", loc, prefix)
	}

	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parsing Location %q: %v", loc, err)
	}
	return u.Query()
}

// assertMintsStateAndPKCE is the core REQ-004 assertion: every redirect to
// the authorization endpoint carries a non-empty state, code_challenge, and
// code_challenge_method=S256, and a redirect_uri that is byte-identical to
// the handler's pre-configured, allowlisted value — never anything supplied
// by the request.
func assertMintsStateAndPKCE(t *testing.T, h *LoginHandler, q url.Values) {
	t.Helper()

	if got := q.Get("state"); got == "" {
		t.Error("redirect missing non-empty state")
	}
	if got := q.Get("code_challenge"); got == "" {
		t.Error("redirect missing non-empty code_challenge")
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want %q", got, "S256")
	}
	if got := q.Get("redirect_uri"); got != h.RedirectURI {
		t.Errorf("redirect_uri = %q, want configured value %q", got, h.RedirectURI)
	}
	if got := q.Get("client_id"); got != h.ClientID {
		t.Errorf("client_id = %q, want configured value %q", got, h.ClientID)
	}
}

// TestLoginHandler_AlwaysMintsStateAndPKCE is the REQ-004 table-driven
// contract test: no matter what an attacker puts in the request (missing
// params, an attacker-chosen state/redirect_uri/client_id/code_challenge
// smuggled in the query string, repeated calls), every resulting redirect
// carries a fresh, non-empty state and PKCE S256 challenge, and a
// redirect_uri/client_id that always come from server-side configuration.
func TestLoginHandler_AlwaysMintsStateAndPKCE(t *testing.T) {
	tests := []struct {
		name    string
		makeReq func() *http.Request
	}{
		{
			name: "bare request, no query string",
			makeReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/auth/login", nil)
			},
		},
		{
			name: "attacker-supplied state/nonce/PKCE/redirect params are ignored",
			makeReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/auth/login?"+url.Values{
					"state":                 {"attacker-chosen-state"},
					"nonce":                 {"attacker-chosen-nonce"},
					"code_challenge":        {"attacker-chosen-challenge"},
					"code_challenge_method": {"plain"},
					"redirect_uri":          {"https://evil.example.com/callback"},
					"client_id":             {"attacker-client-id"},
				}.Encode(), nil)
			},
		},
		{
			name: "unrelated/garbage query params",
			makeReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/auth/login?utm_source=newsletter&foo=&bar=%00%01", nil)
			},
		},
		{
			name: "attacker-supplied Host/Referer/X-Forwarded-Host headers are ignored",
			makeReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
				req.Host = "evil.example.com"
				req.Header.Set("Referer", "https://evil.example.com/")
				req.Header.Set("X-Forwarded-Host", "evil.example.com")
				return req
			},
		},
		{
			name: "POST instead of GET",
			makeReq: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/auth/login", nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestLoginHandler()
			q := authorizeRedirect(t, h, tt.makeReq())
			assertMintsStateAndPKCE(t, h, q)
		})
	}
}

// TestLoginHandler_RepeatedRequestsMintFreshValues drives the same handler
// (and thus the same session store) through several sequential requests and
// asserts every one independently satisfies the state/PKCE contract, and
// that no two requests are minted the same state (each login attempt gets
// its own, unlinkable pending authorization).
func TestLoginHandler_RepeatedRequestsMintFreshValues(t *testing.T) {
	h := newTestLoginHandler()

	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		q := authorizeRedirect(t, h, req)
		assertMintsStateAndPKCE(t, h, q)

		state := q.Get("state")
		if seen[state] {
			t.Fatalf("request %d: state %q was already minted by an earlier request", i, state)
		}
		seen[state] = true
	}
}

// TestLoginHandler_ConcurrentRequestsMintFreshValues drives many concurrent
// requests at the same handler and asserts every single redirect still
// satisfies the state/PKCE contract, with no state collisions — the
// pending-session store must not race or drop entries under contention.
func TestLoginHandler_ConcurrentRequestsMintFreshValues(t *testing.T) {
	h := newTestLoginHandler()

	const n = 50
	states := make([]string, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusFound {
				t.Errorf("request %d: status = %d, want %d", i, rec.Code, http.StatusFound)
				return
			}
			u, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Errorf("request %d: parsing Location: %v", i, err)
				return
			}
			q := u.Query()
			assertMintsStateAndPKCE(t, h, q)
			states[i] = q.Get("state")
		}(i)
	}
	wg.Wait()

	seen := make(map[string]bool, n)
	for i, s := range states {
		if s == "" {
			continue // already reported above
		}
		if seen[s] {
			t.Fatalf("concurrent request %d: state %q collided with another request", i, s)
		}
		seen[s] = true
	}
}

// TestCallbackHandler_StateMismatchIsRejectedGenerically is the REQ-004
// callback-side contract: a callback whose state doesn't match the
// server-side pending session is rejected with the generic login error, and
// the handler never attempts a token exchange — an attacker who can
// trigger a callback (e.g. via a stolen/replayed code and a guessed
// session cookie) cannot get anywhere near an exchange without the correct
// state.
func TestCallbackHandler_StateMismatchIsRejectedGenerically(t *testing.T) {
	var exchangeAttempted bool
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchangeAttempted = true
		t.Error("token endpoint was hit: exchangeCode must not run when state does not match")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer tokenServer.Close()

	sessions := newSessionStore()
	const sessionID = "test-session-id"
	sessions.putPending(sessionID, PendingAuth{
		State:        "correct-state",
		Nonce:        "correct-nonce",
		CodeVerifier: "correct-verifier",
		CreatedAt:    time.Now(),
	})

	h := &CallbackHandler{
		TokenEndpoint: tokenServer.URL,
		ClientID:      "configured-client-id",
		RedirectURI:   "https://rp.example.com/auth/callback",
		Issuer:        "https://idp.example.com",
		Sessions:      sessions,
		HTTPClient:    tokenServer.Client(),
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=attacker-guessed-state&code=some-code", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	body := strings.TrimSpace(rec.Body.String())
	if body != genericLoginError {
		t.Errorf("body = %q, want generic error %q (no leaked detail)", body, genericLoginError)
	}
	if exchangeAttempted {
		t.Error("exchangeAttempted = true, want false: token exchange must not be attempted on state mismatch")
	}
}

// TestCallbackHandler_MissingStateIsRejectedGenerically covers the
// degenerate "no state at all" case, which must fail exactly like a
// mismatched one rather than falling through to some other code path.
func TestCallbackHandler_MissingStateIsRejectedGenerically(t *testing.T) {
	var exchangeAttempted bool
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchangeAttempted = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer tokenServer.Close()

	sessions := newSessionStore()
	const sessionID = "test-session-id"
	sessions.putPending(sessionID, PendingAuth{
		State:        "correct-state",
		Nonce:        "correct-nonce",
		CodeVerifier: "correct-verifier",
		CreatedAt:    time.Now(),
	})

	h := &CallbackHandler{
		TokenEndpoint: tokenServer.URL,
		ClientID:      "configured-client-id",
		RedirectURI:   "https://rp.example.com/auth/callback",
		Issuer:        "https://idp.example.com",
		Sessions:      sessions,
		HTTPClient:    tokenServer.Client(),
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=some-code", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if exchangeAttempted {
		t.Error("exchangeAttempted = true, want false: token exchange must not be attempted with no state")
	}
}

// TestLoginHandler_RedirectURIAlwaysConfiguredValue is a focused restatement
// of the redirect_uri assertion embedded in assertMintsStateAndPKCE above,
// covering the requirement text verbatim: "RedirectURI sent is always the
// configured allowlisted value regardless of request input."
func TestLoginHandler_RedirectURIAlwaysConfiguredValue(t *testing.T) {
	inputs := []string{
		"/auth/login",
		"/auth/login?redirect_uri=https://evil.example.com",
		"/auth/login?redirect_uri=" + url.QueryEscape("javascript:alert(1)"),
		"/auth/login?redirect_uri=",
	}

	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			h := newTestLoginHandler()
			req := httptest.NewRequest(http.MethodGet, in, nil)
			q := authorizeRedirect(t, h, req)
			if got := q.Get("redirect_uri"); got != h.RedirectURI {
				t.Errorf("redirect_uri = %q, want configured value %q", got, h.RedirectURI)
			}
		})
	}
}

// TestNoExportedHelperBypassesStatePKCE is a static, structural check for
// the second REQ-004 scenario: the package's exported API surface must not
// contain a lower-level "build an authorize URL" helper that an integrator
// could call directly and accidentally omit state/PKCE from. It parses
// every non-test .go file in this package and asserts that the only
// function whose body mints a "code_challenge" query parameter is
// LoginHandler.ServeHTTP itself — i.e. minting state/PKCE and constructing
// the authorize URL are inseparable, not split across a public helper.
func TestNoExportedHelperBypassesStatePKCE(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}

	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		if file.Name.Name == "main" {
			files = append(files, file)
		}
	}
	if len(files) == 0 {
		t.Fatalf("package %q not found in parsed sources", "main")
	}

	var mintingFuncs []string
	for _, file := range files {
		src := fset.File(file.Pos())
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}

			start := src.Offset(fn.Body.Pos())
			end := src.Offset(fn.Body.End())
			body := readFileRange(t, src.Name(), start, end)

			if strings.Contains(body, `"code_challenge"`) {
				mintingFuncs = append(mintingFuncs, funcDisplayName(fn))
			}
		}
	}

	if len(mintingFuncs) != 1 {
		t.Fatalf("expected exactly one function to construct an authorize-URL code_challenge parameter, found %d: %v",
			len(mintingFuncs), mintingFuncs)
	}
	if mintingFuncs[0] != "(*LoginHandler).ServeHTTP" {
		t.Fatalf("the sole function minting code_challenge is %q, want %q (LoginHandler.ServeHTTP) — "+
			"a different function constructing authorize-URL parameters suggests a bypassable helper exists",
			mintingFuncs[0], "(*LoginHandler).ServeHTTP")
	}
}

func funcDisplayName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	switch t := fn.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return "(*" + id.Name + ")." + fn.Name.Name
		}
	case *ast.Ident:
		return "(" + t.Name + ")." + fn.Name.Name
	}
	return fn.Name.Name
}

func readFileRange(t *testing.T, path string, start, end int) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if start < 0 || end > len(data) || start > end {
		t.Fatalf("invalid range [%d:%d] for %s (len %d)", start, end, path, len(data))
	}
	return string(data[start:end])
}
