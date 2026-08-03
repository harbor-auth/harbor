package cloudapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/harbor-auth/harbor/internal/gen/db"
)

// memQuerier is a small, stateful in-memory querier fake — unlike
// store_test.go's per-call fakeQuerier, sessions.go's tests need real
// persistence across multiple calls (mint, then a retried mint; mint, then a
// later verification) to exercise idempotent retry and session lookup.
type memQuerier struct {
	mu                   sync.Mutex
	namespaces           map[string]db.CloudNamespace
	operations           map[[2]string]db.CloudOperation
	sessions             map[string]db.CloudSession
	createSessionCalls   int
	createNamespaceCalls int
	softDeleteCalls      int
}

func newMemQuerier() *memQuerier {
	return &memQuerier{
		namespaces: map[string]db.CloudNamespace{},
		operations: map[[2]string]db.CloudOperation{},
		sessions:   map[string]db.CloudSession{},
	}
}

func (m *memQuerier) putNamespace(id, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.namespaces[id] = db.CloudNamespace{ID: id, Status: status}
}

func (m *memQuerier) CreateCloudNamespace(_ context.Context, arg db.CreateCloudNamespaceParams) (db.CloudNamespace, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createNamespaceCalls++
	if _, exists := m.namespaces[arg.ID]; exists {
		return db.CloudNamespace{}, &pgconn.PgError{Code: "23505"}
	}
	ts := pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
	row := db.CloudNamespace{ID: arg.ID, Status: arg.Status, CreatedAt: ts, UpdatedAt: ts}
	m.namespaces[arg.ID] = row
	return row, nil
}

func (m *memQuerier) GetCloudNamespace(_ context.Context, id string) (db.CloudNamespace, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.namespaces[id]
	if !ok {
		return db.CloudNamespace{}, pgx.ErrNoRows
	}
	return row, nil
}

func (m *memQuerier) SoftDeleteCloudNamespace(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.softDeleteCalls++
	row, ok := m.namespaces[id]
	if !ok {
		return nil
	}
	row.DeletedAt = pgtype.Timestamptz{Time: time.Unix(0, 0), Valid: true}
	m.namespaces[id] = row
	return nil
}

func (m *memQuerier) CreateCloudOperation(_ context.Context, arg db.CreateCloudOperationParams) (db.CloudOperation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := [2]string{arg.IdempotencyKey, arg.Operation}
	if _, exists := m.operations[key]; exists {
		return db.CloudOperation{}, &pgconn.PgError{Code: "23505"}
	}
	row := db.CloudOperation{
		IdempotencyKey: arg.IdempotencyKey,
		Operation:      arg.Operation,
		RequestHash:    arg.RequestHash,
		ResponseBody:   arg.ResponseBody,
	}
	m.operations[key] = row
	return row, nil
}

func (m *memQuerier) GetCloudOperation(_ context.Context, arg db.GetCloudOperationParams) (db.CloudOperation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.operations[[2]string{arg.IdempotencyKey, arg.Operation}]
	if !ok {
		return db.CloudOperation{}, pgx.ErrNoRows
	}
	return row, nil
}

func (m *memQuerier) CreateCloudSession(_ context.Context, arg db.CreateCloudSessionParams) (db.CloudSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createSessionCalls++
	row := db.CloudSession{
		SessionID:   arg.SessionID,
		NamespaceID: arg.NamespaceID,
		TokenHash:   arg.TokenHash,
		ExpiresAt:   arg.ExpiresAt,
	}
	m.sessions[arg.SessionID] = row
	return row, nil
}

func (m *memQuerier) GetCloudSession(_ context.Context, sessionID string) (db.CloudSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.sessions[sessionID]
	if !ok {
		return db.CloudSession{}, pgx.ErrNoRows
	}
	return row, nil
}

// newSessionsTestHandler builds a SessionsHandler over a fresh memQuerier
// store with a frozen clock, and pre-populates namespace "ns-a".
func newSessionsTestHandler(t *testing.T) (*SessionsHandler, *memQuerier, time.Time) {
	t.Helper()
	q := newMemQuerier()
	q.putNamespace("ns-a", "active")
	store := NewStore(q)
	h := NewSessionsHandler(store)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	return h, q, now
}

func postSessions(t *testing.T, h *SessionsHandler, idempotencyKey, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/admin/v1/sessions", strings.NewReader(body))
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	rec := httptest.NewRecorder()
	h.PostSessions(rec, req)
	return rec
}

func decodeSessionMintResponse(t *testing.T, rec *httptest.ResponseRecorder) sessionMintResponse {
	t.Helper()
	var resp sessionMintResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	return resp
}

func decodeErrorBody(t *testing.T, rec *httptest.ResponseRecorder) errorBody {
	t.Helper()
	var e errorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error body: %v (body=%s)", err, rec.Body.String())
	}
	return e
}

// --- PostSessions ----------------------------------------------------------

func TestPostSessionsMintsScopedToken(t *testing.T) {
	h, q, now := newSessionsTestHandler(t)

	rec := postSessions(t, h, "key-1", `{"namespace_id":"ns-a"}`)
	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	resp := decodeSessionMintResponse(t, rec)
	if resp.NamespaceID != "ns-a" {
		t.Errorf("NamespaceID = %q, want ns-a", resp.NamespaceID)
	}
	if resp.SessionID == "" || resp.Token == "" {
		t.Fatalf("SessionID/Token not populated: %#v", resp)
	}
	sessionID, secret, ok := splitSessionBearer(resp.Token)
	if !ok || sessionID != resp.SessionID || secret == "" {
		t.Fatalf("Token = %q does not decompose to SessionID %q", resp.Token, resp.SessionID)
	}
	wantExpiry := now.Add(defaultSessionTTL)
	if !resp.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("ExpiresAt = %v, want %v", resp.ExpiresAt, wantExpiry)
	}
	if q.createSessionCalls != 1 {
		t.Errorf("createSessionCalls = %d, want 1", q.createSessionCalls)
	}

	// Only the hash is persisted — the plaintext secret must not appear in
	// the stored row.
	stored := q.sessions[resp.SessionID]
	if string(stored.TokenHash) == secret {
		t.Error("plaintext secret stored verbatim as TokenHash")
	}
}

func TestPostSessionsIdempotentRetryReturnsCachedResponseVerbatim(t *testing.T) {
	h, q, _ := newSessionsTestHandler(t)
	body := `{"namespace_id":"ns-a"}`

	first := postSessions(t, h, "key-1", body)
	if first.Code != 201 {
		t.Fatalf("first status = %d, want 201 (body=%s)", first.Code, first.Body.String())
	}
	firstResp := decodeSessionMintResponse(t, first)

	second := postSessions(t, h, "key-1", body)
	if second.Code != 201 {
		t.Fatalf("second status = %d, want 201 (body=%s)", second.Code, second.Body.String())
	}
	secondResp := decodeSessionMintResponse(t, second)

	if firstResp != secondResp {
		t.Fatalf("retry returned a different response:\nfirst:  %#v\nsecond: %#v", firstResp, secondResp)
	}
	if q.createSessionCalls != 1 {
		t.Errorf("createSessionCalls = %d, want 1 (retry must not mint a second session)", q.createSessionCalls)
	}
}

func TestPostSessionsIdempotencyKeyReusedWithDifferentBodyIsRejected(t *testing.T) {
	h, q, _ := newSessionsTestHandler(t)
	q.putNamespace("ns-b", "active")

	first := postSessions(t, h, "key-1", `{"namespace_id":"ns-a"}`)
	if first.Code != 201 {
		t.Fatalf("first status = %d, want 201 (body=%s)", first.Code, first.Body.String())
	}

	second := postSessions(t, h, "key-1", `{"namespace_id":"ns-b"}`)
	if second.Code != 409 {
		t.Fatalf("second status = %d, want 409 (body=%s)", second.Code, second.Body.String())
	}
	errBody := decodeErrorBody(t, second)
	if errBody.Code != "idempotency_key_reused" {
		t.Errorf("Code = %q, want idempotency_key_reused", errBody.Code)
	}
}

func TestPostSessionsMissingIdempotencyKey(t *testing.T) {
	h, _, _ := newSessionsTestHandler(t)
	rec := postSessions(t, h, "", `{"namespace_id":"ns-a"}`)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if decodeErrorBody(t, rec).Code != "invalid_request" {
		t.Errorf("Code = %q, want invalid_request", decodeErrorBody(t, rec).Code)
	}
}

func TestPostSessionsMissingNamespaceID(t *testing.T) {
	h, _, _ := newSessionsTestHandler(t)
	rec := postSessions(t, h, "key-1", `{}`)
	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestPostSessionsNamespaceNotFound(t *testing.T) {
	h, _, _ := newSessionsTestHandler(t)
	rec := postSessions(t, h, "key-1", `{"namespace_id":"missing-ns"}`)
	if rec.Code != 404 {
		t.Fatalf("status = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}
	if decodeErrorBody(t, rec).Code != "namespace_not_found" {
		t.Errorf("Code = %q, want namespace_not_found", decodeErrorBody(t, rec).Code)
	}
}

func TestPostSessionsDeletedNamespaceIsNotFound(t *testing.T) {
	h, q, _ := newSessionsTestHandler(t)
	if err := NewStore(q).SoftDeleteNamespace(context.Background(), "ns-a"); err != nil {
		t.Fatalf("SoftDeleteNamespace: %v", err)
	}
	rec := postSessions(t, h, "key-1", `{"namespace_id":"ns-a"}`)
	if rec.Code != 404 {
		t.Fatalf("status = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestPostSessionsTTLIsClampedToBounds(t *testing.T) {
	h, _, now := newSessionsTestHandler(t)

	tooLow := 1
	rec := postSessions(t, h, "key-low", `{"namespace_id":"ns-a","ttl_seconds":1}`)
	resp := decodeSessionMintResponse(t, rec)
	if !resp.ExpiresAt.Equal(now.Add(minSessionTTL)) {
		t.Errorf("ttl_seconds=%d: ExpiresAt = %v, want clamped to %v", tooLow, resp.ExpiresAt, now.Add(minSessionTTL))
	}

	rec2 := postSessions(t, h, "key-high", `{"namespace_id":"ns-a","ttl_seconds":999999}`)
	resp2 := decodeSessionMintResponse(t, rec2)
	if !resp2.ExpiresAt.Equal(now.Add(maxSessionTTL)) {
		t.Errorf("ttl_seconds=999999: ExpiresAt = %v, want clamped to %v", resp2.ExpiresAt, now.Add(maxSessionTTL))
	}
}

// --- VerifySessionBearer -----------------------------------------------------

func TestVerifySessionBearerValid(t *testing.T) {
	h, _, _ := newSessionsTestHandler(t)
	mint := decodeSessionMintResponse(t, postSessions(t, h, "key-1", `{"namespace_id":"ns-a"}`))

	sess, err := h.VerifySessionBearer(context.Background(), mint.Token, "ns-a")
	if err != nil {
		t.Fatalf("VerifySessionBearer: unexpected error: %v", err)
	}
	if sess.SessionID != mint.SessionID || sess.NamespaceID != "ns-a" {
		t.Errorf("VerifySessionBearer() = %#v", sess)
	}
}

func TestVerifySessionBearerExpired(t *testing.T) {
	h, _, now := newSessionsTestHandler(t)
	mint := decodeSessionMintResponse(t, postSessions(t, h, "key-1", `{"namespace_id":"ns-a","ttl_seconds":60}`))

	// Advance the clock past expires_at (now + 60s) before verifying.
	h.now = func() time.Time { return now.Add(61 * time.Second) }

	_, err := h.VerifySessionBearer(context.Background(), mint.Token, "ns-a")
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("VerifySessionBearer() error = %v, want ErrSessionExpired", err)
	}
}

func TestVerifySessionBearerExactlyAtExpiryIsExpired(t *testing.T) {
	h, _, now := newSessionsTestHandler(t)
	mint := decodeSessionMintResponse(t, postSessions(t, h, "key-1", `{"namespace_id":"ns-a","ttl_seconds":60}`))

	h.now = func() time.Time { return now.Add(60 * time.Second) }

	_, err := h.VerifySessionBearer(context.Background(), mint.Token, "ns-a")
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("VerifySessionBearer() at exact expiry error = %v, want ErrSessionExpired", err)
	}
}

func TestVerifySessionBearerCrossTenantMismatch(t *testing.T) {
	h, q, _ := newSessionsTestHandler(t)
	q.putNamespace("ns-b", "active")
	mint := decodeSessionMintResponse(t, postSessions(t, h, "key-1", `{"namespace_id":"ns-a"}`))

	_, err := h.VerifySessionBearer(context.Background(), mint.Token, "ns-b")
	if !errors.Is(err, ErrCrossTenantForbidden) {
		t.Fatalf("VerifySessionBearer() error = %v, want ErrCrossTenantForbidden", err)
	}
}

func TestVerifySessionBearerUnknownSessionID(t *testing.T) {
	h, _, _ := newSessionsTestHandler(t)
	_, err := h.VerifySessionBearer(context.Background(), "nonexistent-id.some-secret", "ns-a")
	if !errors.Is(err, ErrInvalidSessionToken) {
		t.Fatalf("VerifySessionBearer() error = %v, want ErrInvalidSessionToken", err)
	}
}

func TestVerifySessionBearerWrongSecret(t *testing.T) {
	h, _, _ := newSessionsTestHandler(t)
	mint := decodeSessionMintResponse(t, postSessions(t, h, "key-1", `{"namespace_id":"ns-a"}`))

	sessionID, _, _ := splitSessionBearer(mint.Token)
	tampered := sessionID + ".wrong-secret"

	_, err := h.VerifySessionBearer(context.Background(), tampered, "ns-a")
	if !errors.Is(err, ErrInvalidSessionToken) {
		t.Fatalf("VerifySessionBearer() error = %v, want ErrInvalidSessionToken", err)
	}
}

func TestVerifySessionBearerMalformedToken(t *testing.T) {
	h, _, _ := newSessionsTestHandler(t)
	for _, bad := range []string{"", "no-dot-in-here", ".leading-dot-secret", "trailing-dot."} {
		if _, err := h.VerifySessionBearer(context.Background(), bad, "ns-a"); !errors.Is(err, ErrInvalidSessionToken) {
			t.Errorf("VerifySessionBearer(%q) error = %v, want ErrInvalidSessionToken", bad, err)
		}
	}
}
