package oidcapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
)

// AdminCredential is one independently-labeled Bearer token accepted by
// AdminAuthMiddleware. Label identifies which credential matched an
// accepted (or would-be) request in the audit log — e.g. "operator" for
// ADMIN_API_TOKEN, "cloud-proxy" for MGMT_HOT_PROXY_TOKEN — so that leaking
// one credential is distinguishable from leaking the other and each can be
// rotated independently.
type AdminCredential struct {
	Label string
	Token string
}

// AdminAuthConfig holds the configuration for the admin authentication
// middleware. Credentials is the set of independently accepted Bearer
// tokens; if empty (or every entry has an empty Token) the middleware is
// fail-closed and rejects every request with 401.
type AdminAuthConfig struct {
	Credentials []AdminCredential
	Logger      *slog.Logger
}

// hashedCredential is a credential's label paired with its pre-computed
// SHA-256 digest, built once at AdminAuthMiddleware construction time so the
// per-request hot path never hashes the configured secret.
type hashedCredential struct {
	label string
	hash  []byte
}

// AdminAuthMiddleware returns an HTTP middleware that enforces Bearer-token
// authentication for admin endpoints. The presented token is hashed with
// SHA-256 and compared in constant time against every configured credential's
// pre-hashed token so the correct value (and which credential, if any,
// matches) cannot be discovered via a timing side-channel: every configured
// credential is compared on every request, never short-circuiting on the
// first match, so the number and order of accepted tokens does not affect
// timing.
//
// Fail-closed: if cfg.Credentials is empty (or every Token is empty), every
// request is rejected with 401. Token values are never logged; only the
// request path, outcome, and — on an accepted request — the label of the
// credential that matched are recorded.
func AdminAuthMiddleware(cfg AdminAuthConfig) func(http.Handler) http.Handler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Pre-hash each configured token once at construction time. An empty
	// Credentials set (or one where every Token is empty) leaves hashed
	// empty, ensuring every request is rejected (fail-closed).
	hashed := make([]hashedCredential, 0, len(cfg.Credentials))
	for _, c := range cfg.Credentials {
		if c.Token == "" {
			continue
		}
		h := sha256.Sum256([]byte(c.Token))
		hashed = append(hashed, hashedCredential{label: c.Label, hash: h[:]})
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			presented := adminBearerToken(r)
			matchedLabel := ""
			if presented != "" {
				presentedHash := adminSHA256(presented)
				for _, c := range hashed {
					if subtle.ConstantTimeCompare(presentedHash, c.hash) == 1 {
						matchedLabel = c.label
					}
				}
			}

			if matchedLabel == "" {
				logger.WarnContext(r.Context(), "admin auth rejected", "path", r.URL.Path)
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				writeError(w, http.StatusUnauthorized, "invalid_token",
					"a valid admin token is required")
				return
			}

			logger.InfoContext(r.Context(), "admin auth accepted", "path", r.URL.Path, "credential", matchedLabel)
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
