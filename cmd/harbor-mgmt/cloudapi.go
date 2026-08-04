// This file wires internal/cloudapi's five /admin/v1/* routes onto the
// production mux (main.go, behind CLOUD_INTEGRATION_ENABLED). It supplies
// the HTTP-layer concerns cloudapi's handlers deliberately leave to their
// caller: service-JWT authentication + scope enforcement ahead of the
// namespace/session handlers (their own doc comments say this is "enforced
// by the auth middleware ahead of this handler"), and a fail-closed,
// per-route rate limit ahead of all five.
package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/cloudapi"
	cloudopenapi "github.com/harbor-auth/harbor/internal/gen/openapi/cloud"
)

// cloudServiceAuth scopes (openspec/changes/harbor-cloud-management-api-contract-2ee993ea/design.md
// §2). keys:rotate is enforced inside KeysHandler.PostKeysRotate itself, not
// here — see registerCloudAPIRoutes.
const (
	scopeSessionsMint    = "sessions:mint"
	scopeNamespacesRead  = "namespaces:read"
	scopeNamespacesWrite = "namespaces:write"
)

// cloudAPILimiters names the five independently-limited /admin/v1/* routes
// (one Redis-backed sliding-window limiter per route, so a burst on one
// operation never starves another).
type cloudAPILimiters struct {
	sessionsMint     clients.RateLimiter
	namespacesCreate clients.RateLimiter
	namespacesGet    clients.RateLimiter
	namespacesDelete clients.RateLimiter
	keysRotate       clients.RateLimiter
}

// newCloudAPILimiters builds the five route limiters over the shared Redis
// client already required by harbor-mgmt for BFF/enrollment state. Limits are
// generous relative to Harbor Cloud's expected call volume (a single
// provisioning-automation caller over one private tunnel) but bounded so a
// misbehaving or compromised caller cannot flood namespace/session/key-rotate
// operations.
func newCloudAPILimiters(client *redis.Client, logger *slog.Logger) cloudAPILimiters {
	limiter := func(name string, limit int, window time.Duration) clients.RateLimiter {
		return clients.NewRedisRateLimiter(client, clients.RateLimiterConfig{
			KeyPrefix: "ratelimit:cloudapi:" + name + ":",
			Limit:     limit,
			Window:    window,
		}, logger)
	}
	return cloudAPILimiters{
		sessionsMint:     limiter("sessions_mint", 120, time.Minute),
		namespacesCreate: limiter("namespaces_create", 30, time.Minute),
		namespacesGet:    limiter("namespaces_get", 300, time.Minute),
		namespacesDelete: limiter("namespaces_delete", 30, time.Minute),
		keysRotate:       limiter("keys_rotate", 10, time.Minute),
	}
}

// registerCloudAPIRoutes registers the five internal, service-JWT-authenticated
// /admin/v1/* routes on mux: session minting, namespace create/get/delete, and
// the key-rotation proxy. Callers gate this behind CLOUD_INTEGRATION_ENABLED —
// harbor-hot's public listener never calls this, and when unregistered the
// mux 404s every /admin/v1/* path.
func registerCloudAPIRoutes(mux *http.ServeMux, verifier *cloudapi.ServiceAuthVerifier, store *cloudapi.Store, keysHandler *cloudapi.KeysHandler, limiters cloudAPILimiters) {
	sessionsHandler := cloudapi.NewSessionsHandler(store)
	server := cloudapi.NewServer(store)

	mux.HandleFunc("POST /admin/v1/sessions", cloudRateLimited(limiters.sessionsMint, "sessions_mint",
		cloudAuthorized(verifier, "POST /admin/v1/sessions", scopeSessionsMint, sessionsHandler.PostSessions)))

	mux.HandleFunc("POST /admin/v1/namespaces", cloudRateLimited(limiters.namespacesCreate, "namespaces_create",
		cloudAuthorized(verifier, "POST /admin/v1/namespaces", scopeNamespacesWrite, func(w http.ResponseWriter, r *http.Request) {
			server.PostAdminV1Namespaces(w, r, cloudopenapi.PostAdminV1NamespacesParams{IdempotencyKey: r.Header.Get("Idempotency-Key")})
		})))

	mux.HandleFunc("GET /admin/v1/namespaces/{id}", cloudRateLimited(limiters.namespacesGet, "namespaces_get",
		cloudAuthorized(verifier, "GET /admin/v1/namespaces/{id}", scopeNamespacesRead, func(w http.ResponseWriter, r *http.Request) {
			server.GetAdminV1Namespace(w, r, r.PathValue("id"))
		})))

	mux.HandleFunc("DELETE /admin/v1/namespaces/{id}", cloudRateLimited(limiters.namespacesDelete, "namespaces_delete",
		cloudAuthorized(verifier, "DELETE /admin/v1/namespaces/{id}", scopeNamespacesWrite, func(w http.ResponseWriter, r *http.Request) {
			server.DeleteAdminV1Namespace(w, r, r.PathValue("id"), cloudopenapi.DeleteAdminV1NamespaceParams{IdempotencyKey: r.Header.Get("Idempotency-Key")})
		})))

	// No cloudAuthorized wrapper here: KeysHandler.PostKeysRotate already
	// calls verifier.Verify itself (it needs the caller's claims to enforce
	// keys:rotate internally). Verifying twice would consume the token's jti
	// on the first (middleware) call and reject the handler's own Verify call
	// as a replay of its own token.
	mux.HandleFunc("POST /admin/v1/keys/rotate", cloudRateLimited(limiters.keysRotate, "keys_rotate", keysHandler.PostKeysRotate))
}

// cloudAuthorized wraps next with cloudServiceAuth bearer verification and a
// required-scope check. route is the audit-log route template passed through
// to cloudapi.WithRoute (a literal path template, never a concrete path with
// ids, matching keys.go's convention).
func cloudAuthorized(verifier *cloudapi.ServiceAuthVerifier, route, scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := cloudBearerToken(r)
		if bearer == "" {
			writeCloudWiringError(w, http.StatusUnauthorized, cloudopenapi.ErrorCodeInvalidToken, "a valid cloudServiceAuth bearer token is required")
			return
		}
		claims, err := verifier.Verify(cloudapi.WithRoute(r.Context(), route), bearer)
		if err != nil {
			writeCloudVerifyError(w, err)
			return
		}
		if !claims.HasScope(scope) {
			writeCloudWiringError(w, http.StatusForbidden, cloudopenapi.ErrorCodeInsufficientScope, "the "+scope+" scope is required")
			return
		}
		next(w, r)
	}
}

// cloudRateLimited wraps next with a fail-closed rate-limit check: a backend
// error (e.g. Redis unavailable) is treated exactly like an over-limit
// request — 429, never an implicit pass — mirroring
// mgmtapi.productionAbuseGate's outage policy for other sensitive endpoints.
func cloudRateLimited(limiter clients.RateLimiter, name string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		allowed, retryAfter, err := limiter.Allow(r.Context(), clients.RateLimitKey(name, cloudRequestSource(r)))
		if err != nil || !allowed {
			if retryAfter <= 0 {
				retryAfter = time.Second
			}
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Round(time.Second)/time.Second)))
			writeCloudWiringError(w, http.StatusTooManyRequests, cloudopenapi.ErrorCodeRateLimited, "too many requests")
			return
		}
		next(w, r)
	}
}

// cloudRequestSource extracts the caller's IP for rate-limit keying, mirroring
// mgmtapi.abuseSource. The mgmt-cloud NodePort Service uses
// externalTrafficPolicy: Local (deploy/helm/templates/service-mgmt.yaml), so
// RemoteAddr is the real WireGuard peer, not a load-balancer address.
func cloudRequestSource(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

// cloudBearerToken extracts the token from an "Authorization: Bearer <token>"
// header, mirroring cloudapi's own (unexported) extractBearerToken /
// oidcapi's adminBearerToken: the scheme is matched case-insensitively per
// RFC 7235 §2.1.
func cloudBearerToken(r *http.Request) string {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(auth[len(prefix):])
}

// writeCloudWiringError renders the shared Error envelope
// (api/openapi/harbor-cloud.yaml `Error` schema) at the given status.
func writeCloudWiringError(w http.ResponseWriter, status int, code cloudopenapi.ErrorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(cloudopenapi.Error{Code: code, Message: message})
}

// writeCloudVerifyError maps a ServiceAuthVerifier.Verify error to the
// appropriate 401 error code, mirroring keys.go's writeVerifyError: a
// replayed jti gets its own stable code, every other verification failure
// (malformed/invalid signature, wrong audience, missing scope, expired, or an
// unconfigured trust anchor/replay guard) is reported as invalid_token so a
// caller never learns which specific check failed.
func writeCloudVerifyError(w http.ResponseWriter, err error) {
	if errors.Is(err, cloudapi.ErrReplayed) {
		writeCloudWiringError(w, http.StatusUnauthorized, cloudopenapi.ErrorCodeTokenReplayed, "the bearer token has already been used")
		return
	}
	writeCloudWiringError(w, http.StatusUnauthorized, cloudopenapi.ErrorCodeInvalidToken, "a valid cloudServiceAuth bearer token is required")
}
