// This file implements POST /admin/v1/keys/rotate — a privileged proxy to
// harbor-hot's existing, unmodified POST /admin/keys/rotate — authenticated
// toward harbor-hot with a second internal admin credential
// (MGMT_HOT_PROXY_TOKEN, label "cloud-proxy") distinct from the operator's
// ADMIN_API_TOKEN, so leaking one credential never leaks the other
// (api/openapi/harbor-cloud.yaml `postAdminV1KeysRotate`, design.md §5).
package cloudapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// scopeKeysRotate is the cloudServiceAuth scope PostKeysRotate requires
// (api/openapi/harbor-cloud.yaml `postAdminV1KeysRotate` security
// requirement). Key rotation is privileged infrastructure — this scope is
// never granted as part of customer self-service.
const scopeKeysRotate = "keys:rotate"

// maxKeysRotateBodyBytes caps the optional JSON request body, which carries
// at most a single boolean flag.
const maxKeysRotateBodyBytes = 4 * 1024

// maxKeysRotateProxyResponseBytes caps the response body read back from
// harbor-hot's proxied rotation call.
const maxKeysRotateProxyResponseBytes = 16 * 1024

// defaultKeysProxyTimeout bounds a single proxied rotation call so a slow or
// hung harbor-hot cannot hold a cloudapi request (and its caller) open
// indefinitely.
const defaultKeysProxyTimeout = 10 * time.Second

// keysRotateRequest is the POST /admin/v1/keys/rotate request body
// (`KeysRotateRequest`). Validated locally (and rejected fast on malformed
// JSON) before ever reaching harbor-hot, but the raw bytes — not a
// re-encoding of this struct — are what's actually forwarded, so the proxy
// call is byte-for-byte what harbor-hot's own PostAdminKeysRotate expects.
type keysRotateRequest struct {
	Emergency *bool `json:"emergency,omitempty"`
}

// KeysHandler implements POST /admin/v1/keys/rotate by verifying the
// caller's cloudServiceAuth bearer, enforcing the keys:rotate scope, and
// proxying to harbor-hot's existing, unmodified POST /admin/keys/rotate.
type KeysHandler struct {
	verifier   *ServiceAuthVerifier
	hotBaseURL string
	proxyToken string
	httpClient *http.Client
}

// NewKeysHandler builds a KeysHandler. verifier authenticates and scopes the
// caller's cloudServiceAuth bearer; hotBaseURL is harbor-hot's internal base
// URL (HARBOR_HOT_INTERNAL_URL, e.g. "http://harbor-hot.internal:8080");
// proxyToken is MGMT_HOT_PROXY_TOKEN — the "cloud-proxy"-labeled admin
// credential this handler presents to harbor-hot, NEVER the operator's
// ADMIN_API_TOKEN. httpClient defaults to a client with
// defaultKeysProxyTimeout when nil. Panics if verifier is nil or hotBaseURL /
// proxyToken is empty — callers must ensure the handler is fully wired
// before startup.
func NewKeysHandler(verifier *ServiceAuthVerifier, hotBaseURL, proxyToken string, httpClient *http.Client) *KeysHandler {
	if verifier == nil {
		panic("cloudapi: nil verifier")
	}
	if hotBaseURL == "" {
		panic("cloudapi: empty hotBaseURL")
	}
	if proxyToken == "" {
		panic("cloudapi: empty proxyToken")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultKeysProxyTimeout}
	}
	return &KeysHandler{
		verifier:   verifier,
		hotBaseURL: strings.TrimRight(hotBaseURL, "/"),
		proxyToken: proxyToken,
		httpClient: httpClient,
	}
}

// PostKeysRotate handles POST /admin/v1/keys/rotate: verifies the caller's
// cloudServiceAuth bearer JWT, requires the keys:rotate scope, then proxies
// the request to harbor-hot's unmodified POST /admin/keys/rotate using
// MGMT_HOT_PROXY_TOKEN (never ADMIN_API_TOKEN) — so harbor-hot's admin audit
// log attributes the call to credential=cloud-proxy, distinct from a direct
// operator call (credential=operator). harbor-hot's rotation state machine
// is itself the source of truth and is safe to call repeatedly, so unlike
// namespace/session handlers this route requires no Idempotency-Key.
//
// Responses:
//   - 200 OK           rotation initiated; body is harbor-hot's response, relayed verbatim
//   - 400 Bad Request  malformed JSON request body
//   - 401 Unauthorized missing/invalid/expired/replayed bearer, or trust anchor unconfigured
//   - 403 Forbidden    bearer lacks the keys:rotate scope
//   - 500 Internal Server Error the proxied call to harbor-hot could not be completed
//
// A non-2xx response harbor-hot itself returns (e.g. its own 401 on a
// misconfigured proxy token, or 500 on rotation failure) is relayed
// verbatim rather than mapped to one of the statuses above — this handler
// only synthesizes an error when authenticating the caller, validating the
// request, or reaching harbor-hot fails before harbor-hot ever responds.
func (h *KeysHandler) PostKeysRotate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	claims, err := h.authorize(ctx, r)
	if err != nil {
		writeVerifyError(w, err)
		return
	}
	if !claims.HasScope(scopeKeysRotate) {
		writeCloudAPIError(w, http.StatusForbidden, "insufficient_scope", "the keys:rotate scope is required")
		return
	}

	rawBody, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxKeysRotateBodyBytes))
	if err != nil {
		writeCloudAPIError(w, http.StatusBadRequest, "invalid_request", "failed to read request body")
		return
	}
	if trimmed := strings.TrimSpace(string(rawBody)); trimmed != "" {
		var req keysRotateRequest
		if err := json.Unmarshal(rawBody, &req); err != nil {
			writeCloudAPIError(w, http.StatusBadRequest, "invalid_request", "malformed JSON request body")
			return
		}
	}

	status, respBody, err := h.proxyRotate(ctx, rawBody)
	if err != nil {
		writeCloudAPIError(w, http.StatusInternalServerError, "server_error", "signing key rotation proxy call to harbor-hot failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(respBody)
}

// authorize extracts and verifies the request's cloudServiceAuth bearer,
// attributing the audit event to this route's template.
func (h *KeysHandler) authorize(ctx context.Context, r *http.Request) (ServiceClaims, error) {
	bearer := extractBearerToken(r)
	if bearer == "" {
		return ServiceClaims{}, ErrInvalidToken
	}
	return h.verifier.Verify(WithRoute(ctx, "POST /admin/v1/keys/rotate"), bearer)
}

// proxyRotate makes the internal HTTP call to harbor-hot's unmodified
// POST /admin/keys/rotate, authenticated with MGMT_HOT_PROXY_TOKEN — never
// ADMIN_API_TOKEN. body is forwarded byte-for-byte.
func (h *KeysHandler) proxyRotate(ctx context.Context, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.hotBaseURL+"/admin/keys/rotate", bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("cloudapi: build proxy request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.proxyToken)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("cloudapi: proxy rotate call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxKeysRotateProxyResponseBytes))
	if err != nil {
		return 0, nil, fmt.Errorf("cloudapi: read proxy response: %w", err)
	}
	return resp.StatusCode, respBody, nil
}

// extractBearerToken extracts the token from an "Authorization: Bearer
// <token>" header, mirroring internal/oidcapi/admin_auth.go's
// adminBearerToken: the scheme is matched case-insensitively per RFC 7235
// §2.1, and "" is returned when the header is absent or not a Bearer
// credential.
func extractBearerToken(r *http.Request) string {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(auth[len(prefix):])
}

// writeVerifyError maps a ServiceAuthVerifier.Verify error to the
// appropriate 401 error code (api/openapi/harbor-cloud.yaml `Error.code`
// enum): a replayed jti gets its own stable code, every other verification
// failure (malformed/invalid signature, wrong audience, missing scope,
// expired, or an unconfigured trust anchor/replay guard) is reported as
// invalid_token so a caller never learns which specific check failed.
func writeVerifyError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrReplayed) {
		writeCloudAPIError(w, http.StatusUnauthorized, "token_replayed", "the bearer token has already been used")
		return
	}
	writeCloudAPIError(w, http.StatusUnauthorized, "invalid_token", "a valid cloudServiceAuth bearer token is required")
}
