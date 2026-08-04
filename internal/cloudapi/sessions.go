// This file implements POST /admin/v1/sessions — minting a short-lived,
// namespace-scoped management session for Harbor Cloud — and the
// session-bearer verification helper namespace-scoped operations use to
// check a presented session token (api/openapi/harbor-cloud.yaml
// `SessionMintRequest`/`SessionMintResponse`, design.md §4).
package cloudapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// operationSessionMint is the `operation` discriminator this handler uses in
// the shared cloud_operations idempotency ledger (Store.CreateOperation /
// GetOperation).
const operationSessionMint = "session.mint"

// Opaque credential sizing. sessionID is a lookup key (not secret — it never
// needs to resist brute force on its own, only the secret half does), secret
// is the actual bearer credential material.
const (
	sessionIDBytes     = 16 // 128-bit opaque session id
	sessionSecretBytes = 32 // 256-bit opaque secret
)

// Session lifetime bounds (api/openapi/harbor-cloud.yaml `SessionMintRequest.ttl_seconds`).
// A caller-requested ttl outside [minSessionTTL, maxSessionTTL] is clamped,
// never rejected — the spec allows the server to clamp.
const (
	defaultSessionTTL = 900 * time.Second
	minSessionTTL     = 60 * time.Second
	maxSessionTTL     = 3600 * time.Second
)

// maxSessionMintBody caps the mint request body. The body is one id string
// and an optional integer, so 4 KB is far beyond any legitimate request.
const maxSessionMintBody = 4 * 1024

// Sentinel errors returned by SessionsHandler.VerifySessionBearer. Each maps
// to a specific HTTP status at the caller's namespace-scoped-operation
// handler: ErrInvalidSessionToken -> 401, ErrSessionExpired -> 410,
// ErrCrossTenantForbidden -> 403 (api/openapi/harbor-cloud.yaml `Error.code`
// `session_expired` / `cross_tenant_forbidden`).
var (
	// ErrInvalidSessionToken covers a malformed bearer, an unknown session
	// id, or a secret that does not match the stored hash.
	ErrInvalidSessionToken = errors.New("cloudapi: invalid session token")

	// ErrSessionExpired is returned once the current time is at or past the
	// session's expires_at.
	ErrSessionExpired = errors.New("cloudapi: session expired")

	// ErrCrossTenantForbidden is returned when a session token minted for one
	// namespace is presented against a different target namespace.
	ErrCrossTenantForbidden = errors.New("cloudapi: session namespace mismatch")
)

// errorBody is the JSON error envelope every /admin/v1/* handler returns
// (api/openapi/harbor-cloud.yaml `Error` schema).
type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// sessionMintRequest is the POST /admin/v1/sessions request body
// (`SessionMintRequest`). TTLSeconds is a pointer so an omitted field is
// distinguishable from an explicit 0 — both fall back to defaultSessionTTL.
type sessionMintRequest struct {
	NamespaceID string `json:"namespace_id"`
	TTLSeconds  *int   `json:"ttl_seconds,omitempty"`
}

// sessionMintResponse is the POST /admin/v1/sessions response body
// (`SessionMintResponse`). Token carries the plaintext bearer credential —
// only its hash is ever persisted, so this is the only place the plaintext
// appears (besides a verbatim idempotent replay of this same cached body).
type sessionMintResponse struct {
	SessionID   string    `json:"session_id"`
	NamespaceID string    `json:"namespace_id"`
	Token       string    `json:"token"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
}

// SessionsHandler implements POST /admin/v1/sessions and the session-bearer
// verification namespace-scoped operations use to authorize a presented
// session token.
type SessionsHandler struct {
	store *Store
	now   func() time.Time
}

// NewSessionsHandler builds a SessionsHandler over store. Panics if store is
// nil — callers must ensure the handler is wired before startup.
func NewSessionsHandler(store *Store) *SessionsHandler {
	if store == nil {
		panic("cloudapi: nil store")
	}
	return &SessionsHandler{store: store, now: time.Now}
}

// PostSessions implements POST /admin/v1/sessions: mints a short-lived,
// namespace-scoped management session. It requires an Idempotency-Key
// header, hashes the normalized request body, and checks the cloud_operations
// ledger before minting — a replay of the same key with the same body
// returns the original response verbatim (including the plaintext token);
// the same key with a different body is rejected. Only the session's
// TokenHash is ever persisted; the plaintext bearer is returned exactly once
// (or replayed verbatim from the ledger on a retried mint).
//
// Responses:
//   - 201 Created   session minted (or, on idempotent replay, the original session)
//   - 400 Bad Request malformed body, missing namespace_id, or missing Idempotency-Key
//   - 404 Not Found the target namespace does not exist or is deleted
//   - 409 Conflict  Idempotency-Key reused with a different request body
//   - 500 Internal Server Error minting or persistence failure
func (h *SessionsHandler) PostSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idempotencyKey == "" {
		writeCloudAPIError(w, http.StatusBadRequest, "invalid_request", "Idempotency-Key header is required")
		return
	}

	rawBody, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSessionMintBody))
	if err != nil {
		writeCloudAPIError(w, http.StatusBadRequest, "invalid_request", "failed to read request body")
		return
	}
	var req sessionMintRequest
	if err := json.Unmarshal(rawBody, &req); err != nil {
		writeCloudAPIError(w, http.StatusBadRequest, "invalid_request", "malformed JSON request body")
		return
	}
	if strings.TrimSpace(req.NamespaceID) == "" {
		writeCloudAPIError(w, http.StatusBadRequest, "invalid_request", "namespace_id is required")
		return
	}

	// Hash the NORMALIZED body (re-marshaled from the parsed request, not the
	// caller's raw bytes) so whitespace/key-order differences between two
	// otherwise-identical requests don't spuriously look like a body change.
	normalized, err := json.Marshal(req)
	if err != nil {
		writeCloudAPIError(w, http.StatusInternalServerError, "server_error", "failed to normalize request body")
		return
	}
	requestHash := sha256Sum(normalized)

	if op, err := h.store.GetOperation(ctx, idempotencyKey, operationSessionMint); err == nil {
		replayCloudOperation(w, op, requestHash)
		return
	} else if !errors.Is(err, ErrOperationNotFound) {
		writeCloudAPIError(w, http.StatusInternalServerError, "server_error", "failed to check idempotency ledger")
		return
	}

	ns, err := h.store.GetNamespace(ctx, req.NamespaceID)
	if err != nil && !errors.Is(err, ErrNamespaceNotFound) {
		writeCloudAPIError(w, http.StatusInternalServerError, "server_error", "failed to look up namespace")
		return
	}
	if errors.Is(err, ErrNamespaceNotFound) || ns.DeletedAt != nil {
		writeCloudAPIError(w, http.StatusNotFound, "namespace_not_found", "the target namespace does not exist or is deleted")
		return
	}

	now := h.now()
	expiresAt := now.Add(clampSessionTTL(req.TTLSeconds))

	sessionID, err := randSessionToken(sessionIDBytes)
	if err != nil {
		writeCloudAPIError(w, http.StatusInternalServerError, "server_error", "failed to mint session")
		return
	}
	secret, err := randSessionToken(sessionSecretBytes)
	if err != nil {
		writeCloudAPIError(w, http.StatusInternalServerError, "server_error", "failed to mint session")
		return
	}
	token := sessionID + "." + secret

	if _, err := h.store.CreateSession(ctx, sessionID, req.NamespaceID, hashSessionSecret(secret), expiresAt); err != nil {
		writeCloudAPIError(w, http.StatusInternalServerError, "server_error", "failed to persist session")
		return
	}

	resp := sessionMintResponse{
		SessionID:   sessionID,
		NamespaceID: req.NamespaceID,
		Token:       token,
		ExpiresAt:   expiresAt.UTC(),
		CreatedAt:   now.UTC(),
	}
	respBody, err := json.Marshal(resp)
	if err != nil {
		writeCloudAPIError(w, http.StatusInternalServerError, "server_error", "failed to encode response")
		return
	}

	if _, err := h.store.CreateOperation(ctx, idempotencyKey, operationSessionMint, requestHash, respBody); err != nil {
		if errors.Is(err, ErrOperationAlreadyExists) {
			// A concurrent request recorded this (key, operation) first — the
			// session above is already durably persisted, so replay whichever
			// response won the race rather than minting (and returning) a
			// second, orphaned plaintext token.
			if op, gerr := h.store.GetOperation(ctx, idempotencyKey, operationSessionMint); gerr == nil {
				replayCloudOperation(w, op, requestHash)
				return
			}
		}
		writeCloudAPIError(w, http.StatusInternalServerError, "server_error", "failed to record idempotency ledger")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(respBody)
}

// VerifySessionBearer resolves and validates a session bearer token (as
// minted by PostSessions: "<session_id>.<secret>") for a namespace-scoped
// operation targeting targetNamespaceID. bearer is the already-extracted
// credential (no "Bearer " prefix), mirroring ServiceAuthVerifier.Verify's
// signature.
//
// It returns ErrInvalidSessionToken for a malformed token, an unknown
// session id, or a secret that does not match the stored hash;
// ErrSessionExpired once the current time is at or past the session's
// expires_at; and ErrCrossTenantForbidden when the session was minted for a
// namespace other than targetNamespaceID.
func (h *SessionsHandler) VerifySessionBearer(ctx context.Context, bearer, targetNamespaceID string) (Session, error) {
	sessionID, secret, ok := splitSessionBearer(bearer)
	if !ok {
		return Session{}, ErrInvalidSessionToken
	}

	sess, err := h.store.GetSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return Session{}, ErrInvalidSessionToken
		}
		return Session{}, fmt.Errorf("cloudapi: verify session bearer: %w", err)
	}

	if subtle.ConstantTimeCompare(hashSessionSecret(secret), sess.TokenHash) != 1 {
		return Session{}, ErrInvalidSessionToken
	}

	if !h.now().Before(sess.ExpiresAt) {
		return Session{}, ErrSessionExpired
	}

	if sess.NamespaceID != targetNamespaceID {
		return Session{}, ErrCrossTenantForbidden
	}

	return sess, nil
}

// splitSessionBearer splits a "<session_id>.<secret>" bearer token into its
// two halves. Neither half may be empty.
func splitSessionBearer(bearer string) (sessionID, secret string, ok bool) {
	idx := strings.IndexByte(bearer, '.')
	if idx <= 0 || idx == len(bearer)-1 {
		return "", "", false
	}
	return bearer[:idx], bearer[idx+1:], true
}

// clampSessionTTL returns the session lifetime for a request, defaulting an
// omitted requested value to defaultSessionTTL and clamping any provided
// value to [minSessionTTL, maxSessionTTL] (the spec permits clamping instead
// of rejecting an out-of-range ttl_seconds).
func clampSessionTTL(requested *int) time.Duration {
	if requested == nil {
		return defaultSessionTTL
	}
	ttl := time.Duration(*requested) * time.Second
	if ttl < minSessionTTL {
		return minSessionTTL
	}
	if ttl > maxSessionTTL {
		return maxSessionTTL
	}
	return ttl
}

// replayCloudOperation writes the response cached by a prior CreateOperation
// call, or 409 idempotency_key_reused if requestHash does not match what was
// originally recorded.
func replayCloudOperation(w http.ResponseWriter, op Operation, requestHash []byte) {
	if subtle.ConstantTimeCompare(op.RequestHash, requestHash) != 1 {
		writeCloudAPIError(w, http.StatusConflict, "idempotency_key_reused",
			"the Idempotency-Key was previously used with a different request body")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(op.ResponseBody)
}

// writeCloudAPIError renders the shared Error envelope at the given status.
func writeCloudAPIError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Code: code, Message: message})
}

// sha256Sum returns the SHA-256 digest of data.
func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// hashSessionSecret returns the SHA-256 of a session's secret half, matching
// what PostSessions persists as Session.TokenHash — the plaintext secret
// never touches the database.
func hashSessionSecret(secret string) []byte {
	return sha256Sum([]byte(secret))
}

// randSessionToken returns n bytes of CSPRNG output encoded as unpadded
// base64url (the same alphabet mgmtapi/register_validate.go uses — it never
// contains '.', so it is safe to join with a literal '.' in a session token).
func randSessionToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
