// This file implements POST /admin/v1/user-sessions — the corporate-SSO
// identity handoff. Harbor Cloud's SAML bridge authenticates a user against
// their own IdP and calls this route to resolve (or create) the
// corresponding Harbor user and mint a one-time login code for them, which
// cmd/harbor-mgmt's GET /login/sso redeems into a real BFF session.
package cloudapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	cloudopenapi "github.com/harbor-auth/harbor/internal/gen/openapi/cloud"
)

// maxUserSessionMintBody caps the mint request body — a namespace id and a
// bounded subject string, comfortably under 4 KB.
const maxUserSessionMintBody = 4 * 1024

// maxSubjectLength mirrors UserSessionMintRequest.subject's documented
// maxLength in api/openapi/harbor-cloud.yaml.
const maxSubjectLength = 1024

// subjectHMACSeparator is written between namespace_id and subject inside
// the HMAC input so a concatenation collision (e.g. namespace_id "ns" +
// subject "a-b" vs. namespace_id "ns-a" + subject "b") can never hash
// identically. 0x1f (ASCII unit separator) cannot appear in either field:
// namespace_id is constrained to namespaceIDPattern, and subject is a
// bounded string from an IdP assertion — 0x1f is a control character no
// legitimate NameID contains.
const subjectHMACSeparator = 0x1f

// minSubjectHMACKeyBytes is the minimum accepted SSO_SUBJECT_HMAC_KEY size —
// the same 256-bit floor every other HMAC/AEAD key in this codebase enforces.
const minSubjectHMACKeyBytes = 32

// subjectHMACKeyVersion is the SSO_SUBJECT_HMAC_KEY version this deployment
// writes new federated_identities rows under (db/migrations/0021's header).
// There is no rotation implementation yet — the raw subject is never stored,
// so a pepper rotation can only re-key rows lazily, at each subject's next
// login, under a new (higher) version. This constant is that future seam.
const subjectHMACKeyVersion int16 = 1

// SubjectHasher computes the HMAC-SHA256 persisted as
// federated_identities.subject_hmac. The raw IdP-asserted subject (e.g. a
// SAML NameID) is NEVER stored or logged — only this digest is, mirroring
// BrowserNonceHash's reasoning (a store compromise yields no re-identifiable
// subject material).
type SubjectHasher struct {
	key []byte
}

// NewSubjectHasher builds a SubjectHasher over key. Returns an error if key
// is shorter than minSubjectHMACKeyBytes — a short key would make the HMAC
// brute-forceable, defeating the point of hashing the subject at all.
func NewSubjectHasher(key []byte) (*SubjectHasher, error) {
	if len(key) < minSubjectHMACKeyBytes {
		return nil, fmt.Errorf("cloudapi: subject HMAC key must be at least %d bytes, got %d", minSubjectHMACKeyBytes, len(key))
	}
	return &SubjectHasher{key: key}, nil
}

// Hash returns HMAC-SHA256(namespaceID || 0x1f || subject). Namespacing the
// input by namespace_id — not just relying on it being part of the resulting
// table row's primary key — means the same subject string presented under
// two different namespaces produces two DIFFERENT digests, so a
// cross-namespace subject collision can never even theoretically resolve to
// the same federated_identities row.
func (h *SubjectHasher) Hash(namespaceID, subject string) []byte {
	mac := hmac.New(sha256.New, h.key)
	mac.Write([]byte(namespaceID))
	mac.Write([]byte{subjectHMACSeparator})
	mac.Write([]byte(subject))
	return mac.Sum(nil)
}

// UserSessionsHandler implements POST /admin/v1/user-sessions.
type UserSessionsHandler struct {
	store  *Store
	hasher *SubjectHasher
	codes  LoginCodeStore
	// region is the region new federated users are enrolled into — this
	// harbor-mgmt instance's own REGION (cmd/harbor-mgmt/main.go). Harbor
	// core stays single-tenant per region (design.md Non-Goals), so a
	// single fixed region is correct here, unlike namespace_id which is
	// caller-supplied.
	region string
	now    func() time.Time
}

// NewUserSessionsHandler builds a UserSessionsHandler. Panics if store,
// hasher, or codes is nil, or region is empty — callers must ensure the
// handler is wired before startup (mirrors NewStore/NewSessionsHandler's
// nil-dependency panics).
func NewUserSessionsHandler(store *Store, hasher *SubjectHasher, codes LoginCodeStore, region string) *UserSessionsHandler {
	if store == nil {
		panic("cloudapi: nil store")
	}
	if hasher == nil {
		panic("cloudapi: nil hasher")
	}
	if codes == nil {
		panic("cloudapi: nil login code store")
	}
	if region == "" {
		panic("cloudapi: empty region")
	}
	return &UserSessionsHandler{store: store, hasher: hasher, codes: codes, region: region, now: time.Now}
}

// PostUserSessions implements POST /admin/v1/user-sessions: resolves (or
// creates) the Harbor user for a corporate-SSO subject and mints a one-time
// login code for them. Requires the `user-sessions:mint` scope (enforced by
// the auth middleware ahead of this handler — cmd/harbor-mgmt/cloudapi.go —
// this handler holds no auth state of its own, mirroring namespaces.go's
// Server and sessions.go's SessionsHandler).
//
// Deliberately takes NO Idempotency-Key and writes NO cloud_operations
// ledger row, unlike every other operation in this contract: identity
// resolution is already idempotent on (namespace_id, subject) via
// federated_identities' primary key, and the only non-idempotent output —
// the one-time login code — must never be persisted at rest for later
// replay (api/openapi/harbor-cloud.yaml's postAdminV1UserSessions
// description). A retried mint simply issues a second code for the same
// resolved user; the first is left to expire unused.
//
// Responses:
//   - 201 Created             login code minted
//   - 400 Bad Request         malformed body, invalid namespace_id/subject, or an unknown JSON field
//   - 403 Forbidden           the resolved user exists but is not active (subject_unavailable), or
//     the presented token's anchor is namespace-restricted (M5) and does not
//     permit namespace_id (cross_tenant_forbidden)
//   - 404 Not Found           the target namespace does not exist or is deleted
//   - 500 Internal Server Error  minting or persistence failure
func (h *UserSessionsHandler) PostUserSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	r.Body = http.MaxBytesReader(w, r.Body, maxUserSessionMintBody)
	dec := json.NewDecoder(r.Body)
	// additionalProperties: false in the spec — reject an unknown field
	// rather than silently ignore it (e.g. a caller mistakenly, or
	// maliciously, attaching an `email`/`groups` field Harbor never stores).
	dec.DisallowUnknownFields()
	var req cloudopenapi.UserSessionMintRequest
	if err := dec.Decode(&req); err != nil {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", "malformed JSON request body")
		return
	}

	if !namespaceIDPattern.MatchString(req.NamespaceId) {
		writeCloudError(w, http.StatusBadRequest, "invalid_request", "namespace_id must be lowercase alphanumeric and hyphens")
		return
	}
	if len(req.Subject) == 0 || len(req.Subject) > maxSubjectLength {
		writeCloudError(w, http.StatusBadRequest, "invalid_subject", "subject must be between 1 and 1024 bytes")
		return
	}

	// M5 — per-anchor namespace binding: the JWT `sub` alone says nothing
	// about which tenant a caller speaks for, so with two bridge keys
	// configured — the entire point of multi-anchor trust — nothing before
	// this would stop tenant A's bridge from minting a login code for a
	// subject in tenant B's namespace. Checked BEFORE the namespace lookup
	// below (and its 404-on-absent branch) so an anchor restricted away from
	// a namespace can't use this endpoint to learn whether that namespace
	// even exists. ServiceClaimsFromContext returns ok=false only when this
	// handler is invoked directly, bypassing the HTTP auth middleware that
	// sets it (e.g. a unit test exercising this handler in isolation) — that
	// case has no anchor to bind to and is treated as unrestricted, exactly
	// as an untested code path already implicitly is today.
	if claims, ok := ServiceClaimsFromContext(ctx); ok && !claims.NamespacePermitted(req.NamespaceId) {
		writeCloudError(w, http.StatusForbidden, "cross_tenant_forbidden", "this signing key is not permitted to mint sessions for the requested namespace")
		return
	}

	ns, err := h.store.GetNamespace(ctx, req.NamespaceId)
	if err != nil && !errors.Is(err, ErrNamespaceNotFound) {
		writeInternalError(w, "cloudapi: get namespace for user session mint", err)
		return
	}
	if errors.Is(err, ErrNamespaceNotFound) || ns.DeletedAt != nil {
		writeCloudError(w, http.StatusNotFound, "namespace_not_found", "the target namespace does not exist or is deleted")
		return
	}

	subjectHMAC := h.hasher.Hash(req.NamespaceId, req.Subject)
	userID, created, err := h.store.ResolveOrCreateFederatedUser(ctx, req.NamespaceId, subjectHMAC, subjectHMACKeyVersion, h.region)
	if err != nil {
		if errors.Is(err, ErrFederatedSubjectUnavailable) {
			writeCloudError(w, http.StatusForbidden, "subject_unavailable", "this subject's account is not available for SSO login")
			return
		}
		writeInternalError(w, "cloudapi: resolve or create federated user", err)
		return
	}

	now := h.now()
	code, err := h.codes.Issue(ctx, LoginCode{UserID: userID, NamespaceID: req.NamespaceId, IssuedAt: now})
	if err != nil {
		writeInternalError(w, "cloudapi: issue login code", err)
		return
	}

	writeCloudJSON(w, http.StatusCreated, cloudopenapi.UserSessionMintResponse{
		LoginCode: code,
		ExpiresAt: now.Add(loginCodeTTL).UTC(),
		Created:   created,
	})
}
