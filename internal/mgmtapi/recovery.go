package mgmtapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/harbor/harbor/internal/identity"
)

// maxRecoveryBody caps recovery request bodies. They carry only small JSON
// payloads (a user id, a method, a code), so a few KB is far beyond any
// legitimate request and stops a flooded endpoint from exhausting memory
// (docs/DESIGN.md §6.5).
const maxRecoveryBody = 4 * 1024

// recoveryCeremonyTTL bounds how long a recovery ceremony (begin → complete)
// stays valid. Recovery is a single, contiguous flow, so the window is short.
const recoveryCeremonyTTL = 10 * time.Minute

// RecoveryScopedSessionCookieName carries the scoped enrollment-only session
// token established by a successful POST /recovery/complete. The user may ONLY
// enroll a fresh passkey with this session until recovery_required is cleared.
const RecoveryScopedSessionCookieName = "harbor_recovery_session"

// ErrRecoveryCeremonyNotFound is returned when a recovery ceremony request id
// is unknown or has expired.
var ErrRecoveryCeremonyNotFound = errors.New("mgmtapi: recovery ceremony not found or expired")

// RecoveryCodeGenerator generates a batch of single-use recovery codes. It is
// satisfied by *identity.RecoveryManager.
type RecoveryCodeGenerator interface {
	GenerateCodes(n int) ([]identity.RecoveryCode, error)
}

// RecoveryCodeStore persists the hashes of a user's recovery codes, replacing
// any existing set. It is satisfied by *clients.DBRecoveryStore.
type RecoveryCodeStore interface {
	StoreRecoveryCodes(ctx context.Context, userID string, codes []identity.RecoveryCode) error
}

// RecoveryVerifier consumes a submitted recovery code for a user, enforcing the
// fail-closed lockout policy. It is satisfied by *identity.RecoveryService and
// returns identity.ErrInvalidCode / identity.ErrUserLocked on failure.
type RecoveryVerifier interface {
	ConsumeCode(ctx context.Context, userID, submittedCode string) error
}

// ScopedSessionIssuer establishes a scoped, enrollment-only session for a user
// who has proven recovery and returns an opaque session token to set as a
// cookie. The session may ONLY enroll a fresh passkey (docs/DESIGN.md §11.1).
type ScopedSessionIssuer interface {
	IssueEnrollmentSession(ctx context.Context, userID string) (token string, err error)
}

// RecoveryFactor is PII-free metadata describing a single registered recovery
// factor (a passkey or hardware security key). It deliberately omits the public
// key and any user identifier — it is only enough for the account owner to tell
// their registered authenticators apart (docs/DESIGN.md §6.5, §10).
type RecoveryFactor struct {
	// ID is an opaque, stable identifier for the credential (its DB id encoded
	// as a string). It is safe to display and to target for future management
	// (e.g. revoke this factor).
	ID string `json:"id"`
	// Type is the factor kind, e.g. "passkey". It mirrors the credential row's
	// type column so hardware keys and platform passkeys are distinguishable.
	Type string `json:"type"`
	// AAGUID identifies the authenticator model (base64url of the raw AAGUID).
	// Empty when the authenticator did not report one. It is model-level, not
	// user-level, so it carries no PII.
	AAGUID string `json:"aaguid,omitempty"`
}

// RecoveryFactorLister lists the recovery factors (passkeys / hardware keys)
// registered to a user via the existing WebAuthn registration path. It is
// satisfied by a thin adapter over the shipped credential store — Harbor treats
// every enrolled passkey as an independent recovery factor, so no new WebAuthn
// code is needed to support fallback authenticators (docs/DESIGN.md §11.1).
type RecoveryFactorLister interface {
	ListFactors(ctx context.Context, userID string) ([]RecoveryFactor, error)
}

// RecoveryRateLimiter gates recovery endpoints. Allow reports whether the call
// identified by key may proceed. Implementations must be safe for concurrent
// use and must NOT retain per-caller PII beyond what is needed to rate-limit.
type RecoveryRateLimiter interface {
	Allow(key string) bool
}

// Recovery-lifecycle audit event types. These are appended to the user-visible,
// append-only audit trail (audit_events, docs/DESIGN.md §10, §11.6) so an
// account owner has a truthful history of every recovery attempt on their
// account.
const (
	// auditRecoveryBegin marks the start of a recovery ceremony (POST
	// /recovery/begin) for the claimed account.
	auditRecoveryBegin = "auth.recovery_begin"
	// auditRecoverySucceeded marks a recovery ceremony whose code was verified
	// (POST /recovery/complete succeeded).
	auditRecoverySucceeded = "auth.recovery_succeeded"
	// auditRecoveryFailed marks a recovery ceremony that failed to complete
	// (wrong/exhausted code, lockout, or region mismatch).
	auditRecoveryFailed = "auth.recovery_failed"
)

// RecoveryAuditLogger appends a recovery-lifecycle event to the user-visible
// audit trail. It is satisfied by a thin adapter over the CreateAuditEvent
// query. region is the opaque regional pin the ceremony ran against; eventType
// is one of the audit* constants above. Emission is best-effort: a failure to
// write the trail must never fail the recovery ceremony (the handler logs and
// carries on), so implementations should not surface transient errors as
// user-facing failures.
type RecoveryAuditLogger interface {
	LogRecoveryEvent(ctx context.Context, userID, region, eventType string) error
}

// RecoveryCeremonyStore bridges POST /recovery/begin and POST /recovery/complete
// by mapping an opaque request id to the user id being recovered plus the
// region the ceremony is pinned to. The stored region enforces region isolation
// (docs/DESIGN.md §5): a ceremony started in one region cannot be completed in
// another.
type RecoveryCeremonyStore interface {
	// Save associates requestID with (userID, region) for the store's TTL.
	Save(ctx context.Context, requestID, userID, region string) error
	// Lookup returns the (userID, region) for requestID, or
	// ErrRecoveryCeremonyNotFound if unknown/expired.
	Lookup(ctx context.Context, requestID string) (userID, region string, err error)
	// Delete removes the ceremony (one-time use after completion).
	Delete(ctx context.Context, requestID string) error
}

// recoveryCeremonyEntry is a stored ceremony plus its expiry.
type recoveryCeremonyEntry struct {
	userID  string
	region  string
	expires time.Time
}

// InMemoryRecoveryCeremonyStore is a development/testing RecoveryCeremonyStore.
// Production wiring should use a shared, short-TTL store (e.g. Redis) so the
// begin→complete handoff works across replicas (docs/DESIGN.md §4.4).
type InMemoryRecoveryCeremonyStore struct {
	mu         sync.Mutex
	ceremonies map[string]recoveryCeremonyEntry
	ttl        time.Duration
	now        func() time.Time
}

// NewInMemoryRecoveryCeremonyStore returns a store whose entries expire after a
// short TTL — recovery is expected to complete within minutes.
func NewInMemoryRecoveryCeremonyStore() *InMemoryRecoveryCeremonyStore {
	return &InMemoryRecoveryCeremonyStore{
		ceremonies: make(map[string]recoveryCeremonyEntry),
		ttl:        recoveryCeremonyTTL,
		now:        time.Now,
	}
}

// Save implements RecoveryCeremonyStore.
func (s *InMemoryRecoveryCeremonyStore) Save(_ context.Context, requestID, userID, region string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ceremonies[requestID] = recoveryCeremonyEntry{
		userID:  userID,
		region:  region,
		expires: s.now().Add(s.ttl),
	}
	return nil
}

// Lookup implements RecoveryCeremonyStore, treating an expired entry as absent
// (and evicting it).
func (s *InMemoryRecoveryCeremonyStore) Lookup(_ context.Context, requestID string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.ceremonies[requestID]
	if !ok {
		return "", "", ErrRecoveryCeremonyNotFound
	}
	if s.now().After(entry.expires) {
		delete(s.ceremonies, requestID)
		return "", "", ErrRecoveryCeremonyNotFound
	}
	return entry.userID, entry.region, nil
}

// Delete implements RecoveryCeremonyStore.
func (s *InMemoryRecoveryCeremonyStore) Delete(_ context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ceremonies, requestID)
	return nil
}

// newRecoveryRequestID returns a 256-bit random, URL-safe opaque id.
func newRecoveryRequestID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// recoveryRegion returns the region a recovery request is pinned to. We use the
// request Host as an opaque, stable region key: the whole ceremony must occur
// against the same regional front door, enforcing region isolation without the
// recovery layer needing to parse hosts itself (docs/DESIGN.md §5). An empty
// Host yields an empty pin, which still requires begin and complete to match.
func recoveryRegion(r *http.Request) string {
	return r.Host
}

// logRecoveryEvent appends a recovery-lifecycle event to the user-visible audit
// trail. It is best-effort by design: a nil logger or an empty userID is a
// no-op, and a write failure is logged (WarnContext) but never propagated, so
// the audit trail can never break the recovery ceremony itself (docs/DESIGN.md
// §11.6). An empty userID is skipped because the trail is keyed by user — paths
// without a resolved user (e.g. an unknown ceremony) have nothing to record.
func (s *Server) logRecoveryEvent(ctx context.Context, userID, region, eventType string) {
	if s.recoveryAudit == nil || userID == "" {
		return
	}
	if err := s.recoveryAudit.LogRecoveryEvent(ctx, userID, region, eventType); err != nil {
		s.logger.WarnContext(ctx, "mgmtapi: recovery audit event write failed", "error", err, "event_type", eventType)
	}
}

// --- POST /recovery/codes ---

// recoveryCodesResponse is the POST /recovery/codes success body. The plaintext
// codes are returned EXACTLY ONCE here and never persisted (docs/DESIGN.md §10).
type recoveryCodesResponse struct {
	Codes []string `json:"codes"`
	Count int      `json:"count"`
}

// PostRecoveryCodes handles POST /recovery/codes — it generates (or
// regenerates) the authenticated user's single-use recovery codes, stores their
// salted hashes, and returns the plaintext codes exactly once. The user id
// comes from the X-Harbor-User-ID header set by upstream authentication; this
// endpoint is for an already-authenticated user setting up recovery, so it is
// distinct from the unauthenticated begin/complete ceremony below.
//
// Responses:
//   - 201 Created             on success ({codes, count})
//   - 401 Unauthorized        missing authenticated user
//   - 429 Too Many Requests   rate limited
//   - 503 Service Unavailable recovery not wired
//   - 500 Internal Server Error generation or persistence failure
func (s *Server) PostRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get(UserIDHeader)
	if userID == "" {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "user authentication required")
		return
	}

	if s.recoveryCodes == nil || s.recoveryStore == nil {
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "recovery service not configured")
		return
	}

	// Rate-limit per authenticated user so a single account cannot churn code
	// generation. The key is the user id, never an IP (no PII series).
	if s.recoveryLimiter != nil && !s.recoveryLimiter.Allow("codes:"+userID) {
		s.writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return
	}

	codes, err := s.recoveryCodes.GenerateCodes(identity.DefaultCodeCount)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: recovery code generation failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to generate recovery codes")
		return
	}

	if err := s.recoveryStore.StoreRecoveryCodes(r.Context(), userID, codes); err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: recovery code persistence failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to store recovery codes")
		return
	}

	plaintext := make([]string, len(codes))
	for i, c := range codes {
		plaintext[i] = c.Plaintext
	}
	s.writeJSON(w, http.StatusCreated, recoveryCodesResponse{Codes: plaintext, Count: len(plaintext)})
}

// --- POST /recovery/begin ---

// recoveryMethodCode is the only recovery method supported today. Fallback
// authenticators (WebAuthn, TOTP) are layered on in later work.
const recoveryMethodCode = "code"

// recoveryBeginRequest is the POST /recovery/begin JSON body.
type recoveryBeginRequest struct {
	UserID string `json:"user_id"`
	Method string `json:"method"`
}

// recoveryBeginResponse is the POST /recovery/begin success body. It returns an
// opaque ceremony id the caller must present to POST /recovery/complete.
type recoveryBeginResponse struct {
	RecoveryRequestID string `json:"recovery_request_id"`
	ExpiresIn         int    `json:"expires_in"`
}

// PostRecoveryBegin handles POST /recovery/begin — it starts an account
// recovery ceremony. The caller is NOT yet authenticated (they have lost their
// passkey), so they claim a user id; possession of a valid recovery code (or,
// later, a fallback authenticator) is proven at POST /recovery/complete.
//
// To avoid leaking whether an account exists, this endpoint ALWAYS issues a
// ceremony id for a well-formed request regardless of whether the claimed user
// exists. Validity is decided uniformly at /recovery/complete via the
// fail-closed verifier. The ceremony is pinned to the request's region so it
// cannot be completed cross-region (docs/DESIGN.md §5).
//
// Responses:
//   - 200 OK                  ceremony started ({recovery_request_id, expires_in})
//   - 400 Bad Request         malformed body or unsupported method
//   - 429 Too Many Requests   rate limited
//   - 503 Service Unavailable recovery not wired
//   - 500 Internal Server Error ceremony persistence failure
func (s *Server) PostRecoveryBegin(w http.ResponseWriter, r *http.Request) {
	if s.recoveryCeremonies == nil {
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "recovery service not configured")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRecoveryBody)
	var req recoveryBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON request body")
		return
	}

	// Default to the code method; only "code" is supported today. Rejecting an
	// unsupported method leaks nothing about any account (it is about the method).
	if req.Method == "" {
		req.Method = recoveryMethodCode
	}
	if req.Method != recoveryMethodCode {
		s.writeError(w, http.StatusBadRequest, "unsupported_method", "unsupported recovery method")
		return
	}
	if req.UserID == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "user_id is required")
		return
	}

	// Rate-limit per claimed user id so begin cannot be used to enumerate or to
	// flood the ceremony store. The key is the claimed user id, never an IP.
	if s.recoveryLimiter != nil && !s.recoveryLimiter.Allow("begin:"+req.UserID) {
		s.writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return
	}

	requestID, err := newRecoveryRequestID()
	if err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: recovery request id generation failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to start recovery")
		return
	}

	if err := s.recoveryCeremonies.Save(r.Context(), requestID, req.UserID, recoveryRegion(r)); err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: recovery ceremony save failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to start recovery")
		return
	}

	// Record the ceremony start on the account's audit trail. Best-effort and
	// keyed by the claimed user id; a non-existent account simply produces no
	// durable event in the adapter (no existence is leaked to the caller).
	s.logRecoveryEvent(r.Context(), req.UserID, recoveryRegion(r), auditRecoveryBegin)

	s.writeJSON(w, http.StatusOK, recoveryBeginResponse{
		RecoveryRequestID: requestID,
		ExpiresIn:         int(recoveryCeremonyTTL.Seconds()),
	})
}

// --- POST /recovery/complete ---

// recoveryCompleteRequest is the POST /recovery/complete JSON body.
type recoveryCompleteRequest struct {
	RecoveryRequestID string `json:"recovery_request_id"`
	Code              string `json:"code"`
}

// recoveryCompleteResponse is the POST /recovery/complete success body.
type recoveryCompleteResponse struct {
	Status string `json:"status"`
}

// PostRecoveryComplete handles POST /recovery/complete — it verifies a recovery
// code against the ceremony started by POST /recovery/begin and, on success,
// establishes a scoped enrollment-only session so the user can register a fresh
// passkey.
//
// Uniform failure: an unknown/expired ceremony, a wrong or exhausted code, and
// a locked-out account ALL return the same generic 401 so the response never
// discloses whether an account exists, whether a code was close, or whether the
// account is locked (docs/DESIGN.md §6.5). The fail-closed verifier still tracks
// lockout server-side, so brute force is throttled even though the client
// cannot distinguish the cases.
//
// Responses:
//   - 200 OK                  recovery succeeded ({status:"recovered"})
//   - 400 Bad Request         malformed body
//   - 401 Unauthorized        uniform recovery failure (any reason)
//   - 429 Too Many Requests   rate limited
//   - 503 Service Unavailable recovery not wired
//   - 500 Internal Server Error scoped-session or ceremony failure
func (s *Server) PostRecoveryComplete(w http.ResponseWriter, r *http.Request) {
	if s.recoveryCeremonies == nil || s.recoveryVerifier == nil {
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "recovery service not configured")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRecoveryBody)
	var req recoveryCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON request body")
		return
	}
	if req.RecoveryRequestID == "" || req.Code == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "recovery_request_id and code are required")
		return
	}

	// Rate-limit per ceremony id so a single ceremony cannot be used to brute
	// force codes faster than the lockout policy intends.
	if s.recoveryLimiter != nil && !s.recoveryLimiter.Allow("complete:"+req.RecoveryRequestID) {
		s.writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return
	}

	userID, pinnedRegion, err := s.recoveryCeremonies.Lookup(r.Context(), req.RecoveryRequestID)
	if err != nil {
		// Unknown/expired ceremony → uniform failure (no existence leak).
		s.writeRecoveryFailed(w)
		return
	}

	// Region isolation: the ceremony must be completed against the same regional
	// front door it was started on. A mismatch is a uniform failure so it does
	// not disclose that the ceremony (and thus the account) exists elsewhere.
	if subtle.ConstantTimeCompare([]byte(pinnedRegion), []byte(recoveryRegion(r))) != 1 {
		s.logRecoveryEvent(r.Context(), userID, pinnedRegion, auditRecoveryFailed)
		s.writeRecoveryFailed(w)
		return
	}

	if err := s.recoveryVerifier.ConsumeCode(r.Context(), userID, req.Code); err != nil {
		// Invalid/exhausted code and lockout both map to the SAME uniform 401 so
		// the response never leaks account existence or lockout state. The
		// verifier has already recorded the failed attempt / lockout server-side.
		if errors.Is(err, identity.ErrInvalidCode) || errors.Is(err, identity.ErrUserLocked) {
			s.logRecoveryEvent(r.Context(), userID, pinnedRegion, auditRecoveryFailed)
			s.writeRecoveryFailed(w)
			return
		}
		s.logger.ErrorContext(r.Context(), "mgmtapi: recovery verify failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to complete recovery")
		return
	}

	// Code consumed: the ceremony is one-time-use, so delete it now (best-effort;
	// the store also TTL-evicts). Deleting before issuing the session prevents a
	// replay of the same code+ceremony.
	if err := s.recoveryCeremonies.Delete(r.Context(), req.RecoveryRequestID); err != nil {
		s.logger.WarnContext(r.Context(), "mgmtapi: recovery ceremony delete failed", "error", err)
	}

	// Establish a scoped enrollment-only session so the user can register a fresh
	// passkey — and ONLY that — until recovery_required is cleared. A nil issuer
	// (dev-scaffold mode) skips the cookie; the caller still gets a 200 so the
	// flow is testable without the full session stack.
	if s.scopedSessions != nil {
		token, err := s.scopedSessions.IssueEnrollmentSession(r.Context(), userID)
		if err != nil {
			s.logger.ErrorContext(r.Context(), "mgmtapi: scoped session issue failed", "error", err)
			s.writeError(w, http.StatusInternalServerError, "server_error", "failed to complete recovery")
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     RecoveryScopedSessionCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(recoveryCeremonyTTL.Seconds()),
		})
	}

	// Recovery is complete: record the success on the account's audit trail so
	// the owner sees exactly when their account was recovered (best-effort).
	s.logRecoveryEvent(r.Context(), userID, pinnedRegion, auditRecoverySucceeded)

	s.writeJSON(w, http.StatusOK, recoveryCompleteResponse{Status: "recovered"})
}

// writeRecoveryFailed writes the single uniform recovery failure used for every
// non-success path at /recovery/complete (unknown ceremony, region mismatch,
// invalid/exhausted code, or lockout). Keeping one code+message guarantees the
// response never leaks which of those conditions occurred (docs/DESIGN.md §6.5).
func (s *Server) writeRecoveryFailed(w http.ResponseWriter) {
	s.writeError(w, http.StatusUnauthorized, "recovery_failed", "recovery could not be completed")
}

// --- GET /recovery/factors ---

// recoveryFactorsResponse is the GET /recovery/factors success body. It lists
// the authenticated user's registered recovery factors (passkeys / hardware
// keys) so they can confirm which authenticators can recover their account.
type recoveryFactorsResponse struct {
	Factors []RecoveryFactor `json:"factors"`
	Count   int              `json:"count"`
}

// ListCredentialsByUser handles GET /recovery/factors — it returns the
// authenticated user's registered recovery factors. Every passkey enrolled via
// the existing WebAuthn registration path is an independent recovery factor, so
// this endpoint simply surfaces those credentials as PII-free metadata; it adds
// no new WebAuthn behaviour (docs/DESIGN.md §11.1). The user id comes from the
// X-Harbor-User-ID header set by upstream authentication.
//
// Responses:
//   - 200 OK                  on success ({factors, count})
//   - 401 Unauthorized        missing authenticated user
//   - 429 Too Many Requests   rate limited
//   - 503 Service Unavailable recovery factor listing not wired
//   - 500 Internal Server Error listing failure
func (s *Server) ListCredentialsByUser(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get(UserIDHeader)
	if userID == "" {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "user authentication required")
		return
	}

	if s.recoveryFactors == nil {
		s.writeError(w, http.StatusServiceUnavailable, "service_unavailable", "recovery service not configured")
		return
	}

	// Rate-limit per authenticated user so listing cannot be abused. The key is
	// the user id, never an IP (no PII series).
	if s.recoveryLimiter != nil && !s.recoveryLimiter.Allow("factors:"+userID) {
		s.writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return
	}

	factors, err := s.recoveryFactors.ListFactors(r.Context(), userID)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "mgmtapi: recovery factor listing failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to list recovery factors")
		return
	}

	// Never emit a null JSON array — an empty list is a valid, expected state.
	if factors == nil {
		factors = []RecoveryFactor{}
	}
	s.writeJSON(w, http.StatusOK, recoveryFactorsResponse{Factors: factors, Count: len(factors)})
}
