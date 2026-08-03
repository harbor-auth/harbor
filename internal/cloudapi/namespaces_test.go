package cloudapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor-auth/harbor/internal/gen/db"
	cloudopenapi "github.com/harbor-auth/harbor/internal/gen/openapi/cloud"
)

// memQuerier is a small stateful in-memory querier fake, distinct from
// store_test.go's per-call fakeQuerier: the namespace handler tests need
// realistic multi-call sequences (create then get, create then delete
// twice, ...) that a single canned closure per method can't express.
type memQuerier struct {
	namespaces map[string]db.CloudNamespace
	operations map[operationKey]db.CloudOperation

	createNamespaceCalls int
	softDeleteCalls      int
}

type operationKey struct {
	idempotencyKey string
	operation      string
}

func newMemQuerier() *memQuerier {
	return &memQuerier{
		namespaces: map[string]db.CloudNamespace{},
		operations: map[operationKey]db.CloudOperation{},
	}
}

func (m *memQuerier) CreateCloudNamespace(_ context.Context, arg db.CreateCloudNamespaceParams) (db.CloudNamespace, error) {
	m.createNamespaceCalls++
	if _, exists := m.namespaces[arg.ID]; exists {
		return db.CloudNamespace{}, errUniqueViolation
	}
	ts := pgtype.Timestamptz{Time: time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC), Valid: true}
	row := db.CloudNamespace{ID: arg.ID, Status: arg.Status, CreatedAt: ts, UpdatedAt: ts}
	m.namespaces[arg.ID] = row
	return row, nil
}

func (m *memQuerier) GetCloudNamespace(_ context.Context, id string) (db.CloudNamespace, error) {
	row, ok := m.namespaces[id]
	if !ok {
		return db.CloudNamespace{}, pgx.ErrNoRows
	}
	return row, nil
}

func (m *memQuerier) SoftDeleteCloudNamespace(_ context.Context, id string) error {
	m.softDeleteCalls++
	row, ok := m.namespaces[id]
	if !ok || row.DeletedAt.Valid {
		// Mirrors the real UPDATE ... WHERE deleted_at IS NULL: affects zero
		// rows, no error, whether id never existed or was already deleted.
		return nil
	}
	ts := pgtype.Timestamptz{Time: time.Date(2026, 8, 3, 13, 0, 0, 0, time.UTC), Valid: true}
	row.DeletedAt = ts
	row.UpdatedAt = ts
	m.namespaces[id] = row
	return nil
}

func (m *memQuerier) CreateCloudOperation(_ context.Context, arg db.CreateCloudOperationParams) (db.CloudOperation, error) {
	key := operationKey{arg.IdempotencyKey, arg.Operation}
	if _, exists := m.operations[key]; exists {
		return db.CloudOperation{}, errUniqueViolation
	}
	row := db.CloudOperation{
		IdempotencyKey: arg.IdempotencyKey,
		Operation:      arg.Operation,
		RequestHash:    arg.RequestHash,
		ResponseBody:   arg.ResponseBody,
		CreatedAt:      pgtype.Timestamptz{Time: time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC), Valid: true},
	}
	m.operations[key] = row
	return row, nil
}

func (m *memQuerier) GetCloudOperation(_ context.Context, arg db.GetCloudOperationParams) (db.CloudOperation, error) {
	row, ok := m.operations[operationKey{arg.IdempotencyKey, arg.Operation}]
	if !ok {
		return db.CloudOperation{}, pgx.ErrNoRows
	}
	return row, nil
}

func (m *memQuerier) CreateCloudSession(context.Context, db.CreateCloudSessionParams) (db.CloudSession, error) {
	panic("memQuerier: CreateCloudSession not used by namespace handler tests")
}

func (m *memQuerier) GetCloudSession(context.Context, string) (db.CloudSession, error) {
	panic("memQuerier: GetCloudSession not used by namespace handler tests")
}

func newTestServer() (*Server, *memQuerier) {
	q := newMemQuerier()
	return NewServer(NewStore(q)), q
}

func doPostNamespace(t *testing.T, srv *Server, idempotencyKey, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/namespaces", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.PostAdminV1Namespaces(rec, req, cloudopenapi.PostAdminV1NamespacesParams{IdempotencyKey: idempotencyKey})
	return rec
}

func doGetNamespace(t *testing.T, srv *Server, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/namespaces/"+id, nil)
	rec := httptest.NewRecorder()
	srv.GetAdminV1Namespace(rec, req, id)
	return rec
}

func doDeleteNamespace(t *testing.T, srv *Server, id, idempotencyKey string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/namespaces/"+id, nil)
	rec := httptest.NewRecorder()
	srv.DeleteAdminV1Namespace(rec, req, id, cloudopenapi.DeleteAdminV1NamespaceParams{IdempotencyKey: idempotencyKey})
	return rec
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) cloudopenapi.Error {
	t.Helper()
	var errResp cloudopenapi.Error
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("decode error response: %v; body = %s", err, rec.Body.String())
	}
	return errResp
}

func TestNewServerPanicsOnNilStore(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewServer(nil) did not panic")
		}
	}()
	NewServer(nil)
}

func TestPostAdminV1NamespacesCreatesNamespace(t *testing.T) {
	srv, _ := newTestServer()
	rec := doPostNamespace(t, srv, "key-1", `{"id":"acme-prod","display_name":"Acme Prod"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	var resp cloudopenapi.NamespaceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Id != "acme-prod" {
		t.Fatalf("Id = %q, want acme-prod", resp.Id)
	}
	if resp.Status != cloudopenapi.Active {
		t.Fatalf("Status = %q, want active", resp.Status)
	}
	if resp.DisplayName == nil || *resp.DisplayName != "Acme Prod" {
		t.Fatalf("DisplayName = %v, want Acme Prod", resp.DisplayName)
	}
	if resp.CreatedAt.IsZero() || resp.UpdatedAt.IsZero() {
		t.Fatalf("CreatedAt/UpdatedAt not populated: %#v", resp)
	}
	if resp.DeletedAt != nil {
		t.Fatalf("DeletedAt = %v, want nil", resp.DeletedAt)
	}
}

func TestPostAdminV1NamespacesIdempotentRetryReturnsOriginalResponse(t *testing.T) {
	srv, q := newTestServer()
	body := `{"id":"acme-prod"}`

	first := doPostNamespace(t, srv, "key-1", body)
	if first.Code != http.StatusCreated {
		t.Fatalf("first status = %d, want 201; body = %s", first.Code, first.Body.String())
	}
	second := doPostNamespace(t, srv, "key-1", body)
	if second.Code != http.StatusCreated {
		t.Fatalf("second status = %d, want 201; body = %s", second.Code, second.Body.String())
	}
	if first.Body.String() != second.Body.String() {
		t.Fatalf("replay body mismatch:\nfirst  = %s\nsecond = %s", first.Body.String(), second.Body.String())
	}
	if q.createNamespaceCalls != 1 {
		t.Fatalf("CreateCloudNamespace called %d times, want 1 (retry must not create a second row)", q.createNamespaceCalls)
	}
}

func TestPostAdminV1NamespacesIdempotencyKeyReusedWithDifferentBody(t *testing.T) {
	srv, _ := newTestServer()
	doPostNamespace(t, srv, "key-1", `{"id":"acme-prod"}`)
	rec := doPostNamespace(t, srv, "key-1", `{"id":"other-ns"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec).Code; got != cloudopenapi.ErrorCodeIdempotencyKeyReused {
		t.Fatalf("error code = %q, want idempotency_key_reused", got)
	}
}

func TestPostAdminV1NamespacesDuplicateIDFreshKeyIsRejected(t *testing.T) {
	srv, _ := newTestServer()
	doPostNamespace(t, srv, "key-1", `{"id":"acme-prod"}`)
	rec := doPostNamespace(t, srv, "key-2", `{"id":"acme-prod"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec).Code; got != cloudopenapi.ErrorCodeNamespaceAlreadyExists {
		t.Fatalf("error code = %q, want namespace_already_exists", got)
	}
}

func TestPostAdminV1NamespacesInvalidIDIsRejected(t *testing.T) {
	srv, _ := newTestServer()
	rec := doPostNamespace(t, srv, "key-1", `{"id":"Not_Valid!"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec).Code; got != cloudopenapi.ErrorCodeInvalidRequest {
		t.Fatalf("error code = %q, want invalid_request", got)
	}
}

func TestPostAdminV1NamespacesMalformedBodyIsRejected(t *testing.T) {
	srv, _ := newTestServer()
	rec := doPostNamespace(t, srv, "key-1", `{"id":`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
}

func TestPostAdminV1NamespacesMissingIdempotencyKeyIsRejected(t *testing.T) {
	srv, _ := newTestServer()
	rec := doPostNamespace(t, srv, "", `{"id":"acme-prod"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
}

func TestGetAdminV1NamespaceFound(t *testing.T) {
	srv, _ := newTestServer()
	doPostNamespace(t, srv, "key-1", `{"id":"acme-prod"}`)

	rec := doGetNamespace(t, srv, "acme-prod")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var resp cloudopenapi.NamespaceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Id != "acme-prod" || resp.Status != cloudopenapi.Active {
		t.Fatalf("response = %#v", resp)
	}
	// display_name is not persisted, so GET never echoes it back.
	if resp.DisplayName != nil {
		t.Fatalf("DisplayName = %v, want nil", resp.DisplayName)
	}
}

func TestGetAdminV1NamespaceNotFound(t *testing.T) {
	srv, _ := newTestServer()
	rec := doGetNamespace(t, srv, "missing")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec).Code; got != cloudopenapi.ErrorCodeNamespaceNotFound {
		t.Fatalf("error code = %q, want namespace_not_found", got)
	}
}

func TestGetAdminV1NamespaceDeletedReturnsNotFound(t *testing.T) {
	srv, _ := newTestServer()
	doPostNamespace(t, srv, "key-1", `{"id":"acme-prod"}`)
	doDeleteNamespace(t, srv, "acme-prod", "del-key-1")

	rec := doGetNamespace(t, srv, "acme-prod")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec).Code; got != cloudopenapi.ErrorCodeNamespaceNotFound {
		t.Fatalf("error code = %q, want namespace_not_found", got)
	}
}

func TestDeleteAdminV1NamespaceSoftDeletesAndReturns204(t *testing.T) {
	srv, q := newTestServer()
	doPostNamespace(t, srv, "key-1", `{"id":"acme-prod"}`)

	rec := doDeleteNamespace(t, srv, "acme-prod", "del-key-1")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("body = %q, want empty (204 No Content)", rec.Body.String())
	}
	if q.softDeleteCalls != 1 {
		t.Fatalf("SoftDeleteCloudNamespace called %d times, want 1", q.softDeleteCalls)
	}

	row := q.namespaces["acme-prod"]
	if !row.DeletedAt.Valid {
		t.Fatal("namespace row not marked deleted")
	}
}

func TestDeleteAdminV1NamespaceIdempotentOnAbsentNamespace(t *testing.T) {
	srv, _ := newTestServer()
	rec := doDeleteNamespace(t, srv, "never-existed", "del-key-1")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteAdminV1NamespaceIdempotentOnAlreadyDeletedNamespace(t *testing.T) {
	srv, q := newTestServer()
	doPostNamespace(t, srv, "key-1", `{"id":"acme-prod"}`)
	doDeleteNamespace(t, srv, "acme-prod", "del-key-1")

	rec := doDeleteNamespace(t, srv, "acme-prod", "del-key-2")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
	}
	if q.softDeleteCalls != 2 {
		t.Fatalf("SoftDeleteCloudNamespace called %d times, want 2 (each fresh key still calls delete on an already-deleted row)", q.softDeleteCalls)
	}
}

func TestDeleteAdminV1NamespaceIdempotentRetryDoesNotDeleteTwice(t *testing.T) {
	srv, q := newTestServer()
	doPostNamespace(t, srv, "key-1", `{"id":"acme-prod"}`)

	first := doDeleteNamespace(t, srv, "acme-prod", "del-key-1")
	second := doDeleteNamespace(t, srv, "acme-prod", "del-key-1")
	if first.Code != http.StatusNoContent || second.Code != http.StatusNoContent {
		t.Fatalf("codes = %d, %d, want 204, 204", first.Code, second.Code)
	}
	if q.softDeleteCalls != 1 {
		t.Fatalf("SoftDeleteCloudNamespace called %d times, want 1 (replay must not re-delete)", q.softDeleteCalls)
	}
}

func TestDeleteAdminV1NamespaceIdempotencyKeyReusedWithDifferentTargetIsRejected(t *testing.T) {
	srv, _ := newTestServer()
	doPostNamespace(t, srv, "key-1", `{"id":"ns-a"}`)
	doPostNamespace(t, srv, "key-2", `{"id":"ns-b"}`)
	doDeleteNamespace(t, srv, "ns-a", "del-key-1")

	rec := doDeleteNamespace(t, srv, "ns-b", "del-key-1")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec).Code; got != cloudopenapi.ErrorCodeIdempotencyKeyReused {
		t.Fatalf("error code = %q, want idempotency_key_reused", got)
	}
}

func TestDeleteAdminV1NamespaceMissingIdempotencyKeyIsRejected(t *testing.T) {
	srv, _ := newTestServer()
	rec := doDeleteNamespace(t, srv, "acme-prod", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
}
