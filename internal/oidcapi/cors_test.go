package oidcapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBrowserClientCORSIsRestrictedToPublicOIDCEndpoints(t *testing.T) {
	ts := newClientAuthFlowServer(t, "none", "")
	h := WithBrowserClientCORS(ts.Config.Handler)
	for _, tc := range []struct {
		method, path string
		allowed      bool
	}{
		{"GET", "/.well-known/openid-configuration", true}, {"GET", "/jwks.json", true}, {"POST", "/token", true},
		{"GET", "/authorize", false}, {"GET", "/authorize/complete", false}, {"GET", "/signin", false},
		{"GET", "/dashboard", false}, {"GET", "/userinfo", true}, {"POST", "/introspect", false},
		{"POST", "/revoke", false}, {"POST", "/admin/keys/rotate", false}, {"GET", "/token", false},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("Origin", "https://customer.example")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if (rec.Header().Get("Access-Control-Allow-Origin") == "*") != tc.allowed {
				t.Fatal("incorrect CORS exposure")
			}
			if rec.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Fatal("browser cookies permitted")
			}
		})
	}
}

func TestBrowserClientCORSPreflight(t *testing.T) {
	calls := 0
	h := WithBrowserClientCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(418) }))
	for _, tc := range []struct {
		path, method, headers string
		status                int
	}{
		{"/token", "POST", "content-type", 204}, {"/jwks.json", "GET", "", 204},
		{"/.well-known/openid-configuration", "GET", "", 204},
		{"/token", "DELETE", "content-type", 403}, {"/token", "POST", "Authorization", 403},
		{"/token", "POST", "Content-Type, X-Admin-Token", 403}, {"/authorize", "GET", "", 418},
	} {
		req := httptest.NewRequest("OPTIONS", tc.path, nil)
		req.Header.Set("Origin", "https://customer.example")
		req.Header.Set("Access-Control-Request-Method", tc.method)
		req.Header.Set("Access-Control-Request-Headers", tc.headers)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.status {
			t.Fatalf("%s %s headers=%s: status=%d", tc.path, tc.method, tc.headers, rec.Code)
		}
		if tc.status != 204 && rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("rejected preflight allowed CORS")
		}
	}
	if calls != 1 {
		t.Fatal("preflight invoked an application handler")
	}
}

func TestPublicClientCrossOriginTokenExchangeStillRequiresPKCE(t *testing.T) {
	ts := newClientAuthFlowServer(t, "none", "")
	h := WithBrowserClientCORS(ts.Config.Handler)
	code := mintCode(t, ts)
	form := validTokenForm(code)
	for _, correct := range []bool{false, true} {
		if !correct {
			form.Set("code_verifier", "wrong")
		} else {
			form = validTokenForm(code)
		}
		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Origin", "https://customer.example")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatal("browser cannot read token response")
		}
		if (rec.Code == 200) != correct {
			t.Fatal("CORS bypassed PKCE or prevented a valid exchange")
		}
	}
}

func TestPublicMetadataCORSDoesNotDependOnOriginHeader(t *testing.T) {
	ts := newClientAuthFlowServer(t, "none", "")
	h := WithBrowserClientCORS(ts.Config.Handler)
	for _, path := range []string{"/.well-known/openid-configuration", "/jwks.json"} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatal("cacheable public metadata can lose browser access after a server-side request")
		}
	}
}

func TestUserInfoBearerPreflight(t *testing.T) {
	handler := WithBrowserClientCORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	for _, path := range []string{"/userinfo", "/token", "/authorize"} {
		req := httptest.NewRequest("OPTIONS", path, nil)
		req.Header.Set("Origin", "https://site.example")
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "Authorization")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if (rec.Header().Get("Access-Control-Allow-Headers") != "") != (path == "/userinfo") {
			t.Fatal("incorrect bearer CORS boundary")
		}
		if rec.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Fatal("CORS allowed cookies")
		}
	}
}
