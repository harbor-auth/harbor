package oidcapi

import (
	"net/http"
	"strings"
)

// WithBrowserClientCORS permits credentialless browser OIDC clients to read
// public metadata, signing keys, and their own token responses (RFC 9700 2.1).
// Authorization/account/admin endpoints are intentionally excluded. CORS is
// not client authentication: /token still enforces binding, PKCE, and the
// registered authentication method, without relying on browser cookies.
func WithBrowserClientCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := ""
		switch r.URL.Path {
		case "/.well-known/openid-configuration", "/jwks.json", "/userinfo":
			method = http.MethodGet
		case "/token":
			method = http.MethodPost
		}
		if method == "" {
			next.ServeHTTP(w, r)
			return
		}
		// Send the same header even without Origin: discovery/JWKS are publicly
		// cacheable and a previous server-side request must not poison browser
		// cache entries with a response lacking CORS headers.
		if r.Method == method {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			next.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodOptions && r.Header.Get("Origin") != "" {
			if r.Header.Get("Access-Control-Request-Method") != method {
				http.Error(w, "CORS method not permitted", http.StatusForbidden)
				return
			}
			for _, header := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
				// Public clients send form bodies, never Authorization or cookies.
				header = strings.TrimSpace(header)
				allowed := header == "" || strings.EqualFold(header, "Content-Type") || (r.URL.Path == "/userinfo" && strings.EqualFold(header, "Authorization"))
				if !allowed {
					http.Error(w, "CORS header not permitted", http.StatusForbidden)
					return
				}
			}
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", method)
			allowedHeaders := "Content-Type"
			if r.URL.Path == "/userinfo" {
				allowedHeaders = "Authorization, Content-Type"
			}
			w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
