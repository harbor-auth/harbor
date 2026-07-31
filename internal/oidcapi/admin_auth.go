package oidcapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
)

// AdminAuthConfig holds the configuration for the admin authentication
// middleware. Token is the plaintext shared secret; if empty the middleware is
// fail-closed and rejects every request with 401.
type AdminAuthConfig struct {
	Token  string
	Logger *slog.Logger
}

// AdminAuthMiddleware returns an HTTP middleware that enforces Bearer-token
// authentication for admin endpoints. The presented token is hashed with
// SHA-256 and compared in constant time against the pre-hashed configured
// token so the correct value cannot be discovered via a timing side-channel.
//
// Fail-closed: if cfg.Token is empty, every request is rejected with 401.
// The token is never logged; only the request path and outcome are recorded.
func AdminAuthMiddleware(cfg AdminAuthConfig) func(http.Handler) http.Handler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Pre-hash the configured token once at construction time. An empty Token
	// leaves tokenHash nil, ensuring every request is rejected (fail-closed).
	var tokenHash []byte
	if cfg.Token != "" {
		h := sha256.Sum256([]byte(cfg.Token))
		tokenHash = h[:]
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			presented := adminBearerToken(r)
			authorized := presented != "" && tokenHash != nil &&
				subtle.ConstantTimeCompare(adminSHA256(presented), tokenHash) == 1

			if !authorized {
				logger.WarnContext(r.Context(), "admin auth rejected", "path", r.URL.Path)
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				writeError(w, http.StatusUnauthorized, "invalid_token",
					"a valid admin token is required")
				return
			}

			logger.InfoContext(r.Context(), "admin auth accepted", "path", r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}

// adminBearerToken extracts the token from an "Authorization: Bearer <token>"
// header, returning "" when the header is absent or not a Bearer credential.
// The scheme is matched case-insensitively per RFC 7235 §2.1.
func adminBearerToken(r *http.Request) string {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(auth[len(prefix):])
}

// adminSHA256 returns the SHA-256 digest of s as a byte slice.
func adminSHA256(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}
