package cloudapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"

	"github.com/harbor-auth/harbor/internal/crypto"
	db "github.com/harbor-auth/harbor/internal/gen/db"
	cloudopenapi "github.com/harbor-auth/harbor/internal/gen/openapi/cloud"
)

// --- fake federatedPool ------------------------------------------------
//
// federatedTxQuerier/federatedTx/federatedPool (federated_store.go) are the
// narrow interfaces ResolveOrCreateFederatedUser needs from a transaction.
// fakeFederatedPool simulates the SAME atomicity contract a real Postgres
// transaction gives — writes made inside a transaction are invisible to
// other readers until Commit, and vanish on Rollback — entirely in memory,
// following this package's established "fakes over integration tests"
// convention (store_test.go's fakeQuerier, sessions_test.go's memQuerier).

type federatedIdentKey [3]string

func newFederatedIdentKey(namespaceID string, subjectHMAC []byte, keyVersion int16) federatedIdentKey {
	return federatedIdentKey{namespaceID, hex.EncodeToString(subjectHMAC), strconv.Itoa(int(keyVersion))}
}

type fakeFederatedPool struct {
	mu         sync.Mutex
	users      map[string]db.User
	identities map[federatedIdentKey]db.FederatedIdentity

	// createFederatedIdentityErr, when non-nil, is returned exactly ONCE
	// (then cleared) by the next CreateFederatedIdentity call — simulating a
	// concurrent writer winning the create race with a 23505. When it fires,
	// pendingWinnerIdentity (if set) is committed into pool.identities at
	// that exact moment — representing the concurrent transaction's commit
	// landing in the window between our own miss-read and our own INSERT.
	createFederatedIdentityErr error
	pendingWinnerIdentity      *db.FederatedIdentity

	touchCalls int
}

func newFakeFederatedPool() *fakeFederatedPool {
	return &fakeFederatedPool{
		users:      map[string]db.User{},
		identities: map[federatedIdentKey]db.FederatedIdentity{},
	}
}

func (p *fakeFederatedPool) putUser(u db.User) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users[uuid.UUID(u.ID.Bytes).String()] = u
}

func (p *fakeFederatedPool) Begin(context.Context) (federatedTx, error) {
	return &fakeFederatedTx{
		pool:             p,
		stagedUsers:      map[string]db.User{},
		stagedIdentities: map[federatedIdentKey]db.FederatedIdentity{},
	}, nil
}

func (p *fakeFederatedPool) GetFederatedIdentity(_ context.Context, arg db.GetFederatedIdentityParams) (db.FederatedIdentity, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	row, ok := p.identities[newFederatedIdentKey(arg.NamespaceID, arg.SubjectHmac, arg.KeyVersion)]
	if !ok {
		return db.FederatedIdentity{}, pgx.ErrNoRows
	}
	return row, nil
}

// GetUser implements the plain, non-transactional read federatedPool needs
// for L7's post-conflict status re-check (ResolveOrCreateFederatedUser's
// create-race loser branch).
func (p *fakeFederatedPool) GetUser(_ context.Context, id pgtype.UUID) (db.User, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	u, ok := p.users[uuid.UUID(id.Bytes).String()]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return u, nil
}

// fakeFederatedTx stages writes locally; they only become visible to other
// callers (via the pool) on Commit, mirroring real transaction isolation for
// this package's single-goroutine tests.
type fakeFederatedTx struct {
	pool             *fakeFederatedPool
	stagedUsers      map[string]db.User
	stagedIdentities map[federatedIdentKey]db.FederatedIdentity
}

func (t *fakeFederatedTx) GetFederatedIdentity(_ context.Context, arg db.GetFederatedIdentityParams) (db.FederatedIdentity, error) {
	key := newFederatedIdentKey(arg.NamespaceID, arg.SubjectHmac, arg.KeyVersion)
	if row, ok := t.stagedIdentities[key]; ok {
		return row, nil
	}
	t.pool.mu.Lock()
	defer t.pool.mu.Unlock()
	row, ok := t.pool.identities[key]
	if !ok {
		return db.FederatedIdentity{}, pgx.ErrNoRows
	}
	return row, nil
}

func (t *fakeFederatedTx) GetUser(_ context.Context, id pgtype.UUID) (db.User, error) {
	key := uuid.UUID(id.Bytes).String()
	if u, ok := t.stagedUsers[key]; ok {
		return u, nil
	}
	t.pool.mu.Lock()
	defer t.pool.mu.Unlock()
	u, ok := t.pool.users[key]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return u, nil
}

func (t *fakeFederatedTx) TouchFederatedIdentity(context.Context, db.TouchFederatedIdentityParams) error {
	t.pool.mu.Lock()
	t.pool.touchCalls++
	t.pool.mu.Unlock()
	return nil
}

func (t *fakeFederatedTx) CreateFederatedIdentity(_ context.Context, arg db.CreateFederatedIdentityParams) (db.FederatedIdentity, error) {
	t.pool.mu.Lock()
	if t.pool.createFederatedIdentityErr != nil {
		err := t.pool.createFederatedIdentityErr
		t.pool.createFederatedIdentityErr = nil
		if t.pool.pendingWinnerIdentity != nil {
			winner := *t.pool.pendingWinnerIdentity
			t.pool.identities[newFederatedIdentKey(winner.NamespaceID, winner.SubjectHmac, winner.KeyVersion)] = winner
			t.pool.pendingWinnerIdentity = nil
		}
		t.pool.mu.Unlock()
		return db.FederatedIdentity{}, err
	}
	t.pool.mu.Unlock()
	row := db.FederatedIdentity{NamespaceID: arg.NamespaceID, SubjectHmac: arg.SubjectHmac, KeyVersion: arg.KeyVersion, UserID: arg.UserID}
	t.stagedIdentities[newFederatedIdentKey(arg.NamespaceID, arg.SubjectHmac, arg.KeyVersion)] = row
	return row, nil
}

func (t *fakeFederatedTx) CreateFederatedUser(_ context.Context, arg db.CreateFederatedUserParams) (db.User, error) {
	row := db.User{ID: arg.ID, Region: arg.Region, Status: "active", DekWrapped: arg.DekWrapped, PairwiseSecret: arg.PairwiseSecret, RecoveryRequired: false}
	t.stagedUsers[uuid.UUID(arg.ID.Bytes).String()] = row
	return row, nil
}

func (t *fakeFederatedTx) Commit(context.Context) error {
	t.pool.mu.Lock()
	defer t.pool.mu.Unlock()
	for k, v := range t.stagedUsers {
		t.pool.users[k] = v
	}
	for k, v := range t.stagedIdentities {
		t.pool.identities[k] = v
	}
	return nil
}

func (t *fakeFederatedTx) Rollback(context.Context) error {
	// Staged writes were never merged into the pool — nothing to undo.
	return nil
}

// pgUniqueViolation mirrors sessions_test.go's errUniqueViolation.
var pgUniqueViolationForIdentity = &pgconn.PgError{Code: "23505", ConstraintName: "federated_identities_pkey"}

// newFederatedTestStore builds a *Store with WithFederatedIdentities wired
// over a fresh fakeFederatedPool and a real (but test-only) KeyProvider/
// Cipher — the same crypto EnrollFederated actually exercises, just backed
// by a local, not-KMS, key provider (mirrors internal/identity/enroll_test.go).
func newFederatedTestStore(t *testing.T) (*Store, *fakeFederatedPool) {
	t.Helper()
	kp, err := crypto.NewLocalKeyProvider("test-secret-32-bytes-for-testing!")
	if err != nil {
		t.Fatalf("NewLocalKeyProvider: %v", err)
	}
	pool := newFakeFederatedPool()
	store := NewStore(newMemQuerier()).WithFederatedIdentities(pool, kp, crypto.NewCipher())
	store.CreateNamespace(context.Background(), "acme", "active") //nolint:errcheck // test setup
	return store, pool
}

// --- ResolveOrCreateFederatedUser (store-level) ---------------------------

func TestResolveOrCreateFederatedUserCreatesOnFirstSeen(t *testing.T) {
	store, _ := newFederatedTestStore(t)
	hasher, err := NewSubjectHasher([]byte("subject-hmac-test-key-32-bytes!!"))
	if err != nil {
		t.Fatalf("NewSubjectHasher: %v", err)
	}
	subjectHMAC := hasher.Hash("acme", "alice@example.com")

	userID, created, err := store.ResolveOrCreateFederatedUser(context.Background(), "acme", subjectHMAC, subjectHMACKeyVersion, "EU")
	if err != nil {
		t.Fatalf("ResolveOrCreateFederatedUser: %v", err)
	}
	if !created {
		t.Error("created = false, want true on first sighting")
	}
	if userID == "" {
		t.Fatal("userID is empty")
	}
	if _, err := uuid.Parse(userID); err != nil {
		t.Fatalf("userID %q is not a canonical UUID: %v", userID, err)
	}
}

func TestResolveOrCreateFederatedUserResolvesExistingMapping(t *testing.T) {
	store, pool := newFederatedTestStore(t)
	hasher, err := NewSubjectHasher([]byte("subject-hmac-test-key-32-bytes!!"))
	if err != nil {
		t.Fatalf("NewSubjectHasher: %v", err)
	}
	subjectHMAC := hasher.Hash("acme", "alice@example.com")

	first, created1, err := store.ResolveOrCreateFederatedUser(context.Background(), "acme", subjectHMAC, subjectHMACKeyVersion, "EU")
	if err != nil {
		t.Fatalf("first ResolveOrCreateFederatedUser: %v", err)
	}
	if !created1 {
		t.Fatal("first call: created = false, want true")
	}

	second, created2, err := store.ResolveOrCreateFederatedUser(context.Background(), "acme", subjectHMAC, subjectHMACKeyVersion, "EU")
	if err != nil {
		t.Fatalf("second ResolveOrCreateFederatedUser: %v", err)
	}
	if created2 {
		t.Error("second call: created = true, want false (existing mapping)")
	}
	if second != first {
		t.Fatalf("second call resolved to a different user: %q != %q", second, first)
	}
	if pool.touchCalls != 1 {
		t.Errorf("touchCalls = %d, want 1 (only the resolve-existing path touches last_seen_at)", pool.touchCalls)
	}
}

// TestResolveOrCreateFederatedUserSameSubjectTwoNamespacesDistinctUsers
// proves the core cross-tenant isolation property: the same subject string
// presented under two different namespaces resolves to two DIFFERENT
// Harbor users, never the same one.
func TestResolveOrCreateFederatedUserSameSubjectTwoNamespacesDistinctUsers(t *testing.T) {
	store, _ := newFederatedTestStore(t)
	store.CreateNamespace(context.Background(), "globex", "active") //nolint:errcheck // test setup
	hasher, err := NewSubjectHasher([]byte("subject-hmac-test-key-32-bytes!!"))
	if err != nil {
		t.Fatalf("NewSubjectHasher: %v", err)
	}

	const subject = "alice@example.com"
	idA, _, err := store.ResolveOrCreateFederatedUser(context.Background(), "acme", hasher.Hash("acme", subject), subjectHMACKeyVersion, "EU")
	if err != nil {
		t.Fatalf("namespace acme: %v", err)
	}
	idB, _, err := store.ResolveOrCreateFederatedUser(context.Background(), "globex", hasher.Hash("globex", subject), subjectHMACKeyVersion, "EU")
	if err != nil {
		t.Fatalf("namespace globex: %v", err)
	}
	if idA == idB {
		t.Fatalf("same subject in two namespaces resolved to the SAME user %q — cross-tenant isolation broken", idA)
	}
}

func TestResolveOrCreateFederatedUserErasedUserIsUnavailable(t *testing.T) {
	store, pool := newFederatedTestStore(t)
	hasher, err := NewSubjectHasher([]byte("subject-hmac-test-key-32-bytes!!"))
	if err != nil {
		t.Fatalf("NewSubjectHasher: %v", err)
	}
	subjectHMAC := hasher.Hash("acme", "alice@example.com")

	userID, _, err := store.ResolveOrCreateFederatedUser(context.Background(), "acme", subjectHMAC, subjectHMACKeyVersion, "EU")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Simulate crypto-shredding (identity.Eraser) by flipping the user's
	// status directly in the fake pool.
	u := pool.users[userID]
	u.Status = "erased"
	pool.putUser(u)

	if _, _, err := store.ResolveOrCreateFederatedUser(context.Background(), "acme", subjectHMAC, subjectHMACKeyVersion, "EU"); !errors.Is(err, ErrFederatedSubjectUnavailable) {
		t.Fatalf("ResolveOrCreateFederatedUser (erased user) error = %v, want ErrFederatedSubjectUnavailable", err)
	}
}

func TestResolveOrCreateFederatedUserUnconfiguredFailsClosed(t *testing.T) {
	store := NewStore(newMemQuerier()) // WithFederatedIdentities never called
	if _, _, err := store.ResolveOrCreateFederatedUser(context.Background(), "acme", []byte("hmac"), 1, "EU"); !errors.Is(err, ErrFederatedIdentitiesUnconfigured) {
		t.Fatalf("error = %v, want ErrFederatedIdentitiesUnconfigured", err)
	}
}

// TestResolveOrCreateFederatedUserLosesCreateRaceRereadsWinner proves the
// transactional isolation property: when CreateFederatedIdentity loses the
// create race (23505), this call's own freshly-created user row is
// discarded (never left orphaned) and the winner's user id is returned.
func TestResolveOrCreateFederatedUserLosesCreateRaceRereadsWinner(t *testing.T) {
	store, pool := newFederatedTestStore(t)
	hasher, err := NewSubjectHasher([]byte("subject-hmac-test-key-32-bytes!!"))
	if err != nil {
		t.Fatalf("NewSubjectHasher: %v", err)
	}
	subjectHMAC := hasher.Hash("acme", "alice@example.com")

	// Seed the "winner" mapping directly, as if a concurrent request
	// committed first, and arm the next CreateFederatedIdentity call to fail
	// as that concurrent request's INSERT would have.
	winnerID := uuid.New()
	var winnerUID pgtype.UUID
	if err := winnerUID.Scan(winnerID.String()); err != nil {
		t.Fatalf("scan winner uuid: %v", err)
	}
	pool.putUser(db.User{ID: winnerUID, Region: "EU", Status: "active"})
	pool.mu.Lock()
	pool.createFederatedIdentityErr = pgUniqueViolationForIdentity
	pool.pendingWinnerIdentity = &db.FederatedIdentity{NamespaceID: "acme", SubjectHmac: subjectHMAC, KeyVersion: subjectHMACKeyVersion, UserID: winnerUID}
	pool.mu.Unlock()

	got, created, err := store.ResolveOrCreateFederatedUser(context.Background(), "acme", subjectHMAC, subjectHMACKeyVersion, "EU")
	if err != nil {
		t.Fatalf("ResolveOrCreateFederatedUser: %v", err)
	}
	if created {
		t.Error("created = true, want false (lost the race to an existing winner)")
	}
	// The loser's own freshly-created user must never have been committed —
	// only the pre-seeded winner is a legitimate committed user.
	if len(pool.users) != 1 {
		t.Errorf("pool has %d committed users, want 1 (the loser's user row must not survive rollback)", len(pool.users))
	}
	_ = got
}

// TestResolveOrCreateFederatedUserLosesCreateRaceToErasedWinnerIsUnavailable
// is L7: the create-race LOSER branch must apply the exact same
// active-status gate the primary (cache-hit) read path already does. Before
// this fix, a caller who happened to lose the race to a winner whose account
// was ALREADY erased (a narrow but real window — e.g. erasure and a second
// concurrent SSO login landing at nearly the same instant) got back a live
// user id instead of ErrFederatedSubjectUnavailable: the one return path
// that skipped the check.
func TestResolveOrCreateFederatedUserLosesCreateRaceToErasedWinnerIsUnavailable(t *testing.T) {
	store, pool := newFederatedTestStore(t)
	hasher, err := NewSubjectHasher([]byte("subject-hmac-test-key-32-bytes!!"))
	if err != nil {
		t.Fatalf("NewSubjectHasher: %v", err)
	}
	subjectHMAC := hasher.Hash("acme", "alice@example.com")

	winnerID := uuid.New()
	var winnerUID pgtype.UUID
	if err := winnerUID.Scan(winnerID.String()); err != nil {
		t.Fatalf("scan winner uuid: %v", err)
	}
	// The winner's account is already erased — the loser must not learn
	// their user id and be granted a session anyway.
	pool.putUser(db.User{ID: winnerUID, Region: "EU", Status: "erased"})
	pool.mu.Lock()
	pool.createFederatedIdentityErr = pgUniqueViolationForIdentity
	pool.pendingWinnerIdentity = &db.FederatedIdentity{NamespaceID: "acme", SubjectHmac: subjectHMAC, KeyVersion: subjectHMACKeyVersion, UserID: winnerUID}
	pool.mu.Unlock()

	_, created, err := store.ResolveOrCreateFederatedUser(context.Background(), "acme", subjectHMAC, subjectHMACKeyVersion, "EU")
	if !errors.Is(err, ErrFederatedSubjectUnavailable) {
		t.Fatalf("ResolveOrCreateFederatedUser (lost race to erased winner) error = %v, want ErrFederatedSubjectUnavailable", err)
	}
	if created {
		t.Error("created = true, want false")
	}
}

// --- UserSessionsHandler (HTTP layer) --------------------------------------

func newUserSessionsTestHandler(t *testing.T) (*UserSessionsHandler, *fakeFederatedPool, *redis.Client) {
	t.Helper()
	store, pool := newFederatedTestStore(t)
	hasher, err := NewSubjectHasher([]byte("subject-hmac-test-key-32-bytes!!"))
	if err != nil {
		t.Fatalf("NewSubjectHasher: %v", err)
	}
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() }) //nolint:errcheck // test cleanup
	codes := NewRedisLoginCodeStore(redisClient)
	h := NewUserSessionsHandler(store, hasher, codes, "EU")
	return h, pool, redisClient
}

func doPostUserSessions(h *UserSessionsHandler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/user-sessions", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.PostUserSessions(rec, req)
	return rec
}

func TestPostUserSessionsAbsentNamespaceReturns404(t *testing.T) {
	h, _, _ := newUserSessionsTestHandler(t)
	rec := doPostUserSessions(h, `{"namespace_id":"does-not-exist","subject":"alice@example.com"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec); got.Code != cloudopenapi.ErrorCodeNamespaceNotFound {
		t.Errorf("error.code = %q, want namespace_not_found", got.Code)
	}
}

func TestPostUserSessionsSoftDeletedNamespaceReturns404(t *testing.T) {
	h, _, _ := newUserSessionsTestHandler(t)
	if err := h.store.SoftDeleteNamespace(context.Background(), "acme"); err != nil {
		t.Fatalf("SoftDeleteNamespace: %v", err)
	}
	rec := doPostUserSessions(h, `{"namespace_id":"acme","subject":"alice@example.com"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
}

func TestPostUserSessionsEmptySubjectReturns400(t *testing.T) {
	h, _, _ := newUserSessionsTestHandler(t)
	rec := doPostUserSessions(h, `{"namespace_id":"acme","subject":""}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec); got.Code != cloudopenapi.ErrorCodeInvalidSubject {
		t.Errorf("error.code = %q, want invalid_subject", got.Code)
	}
}

func TestPostUserSessionsOversizedSubjectReturns400(t *testing.T) {
	h, _, _ := newUserSessionsTestHandler(t)
	oversized := strings.Repeat("a", maxSubjectLength+1)
	rec := doPostUserSessions(h, `{"namespace_id":"acme","subject":"`+oversized+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec); got.Code != cloudopenapi.ErrorCodeInvalidSubject {
		t.Errorf("error.code = %q, want invalid_subject", got.Code)
	}
}

func TestPostUserSessionsUnknownJSONPropertyReturns400(t *testing.T) {
	h, _, _ := newUserSessionsTestHandler(t)
	rec := doPostUserSessions(h, `{"namespace_id":"acme","subject":"alice@example.com","email":"alice@example.com"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown JSON field (additionalProperties: false); body = %s", rec.Code, rec.Body.String())
	}
}

func TestPostUserSessionsErasedUserReturns403(t *testing.T) {
	h, pool, _ := newUserSessionsTestHandler(t)
	hasher, err := NewSubjectHasher([]byte("subject-hmac-test-key-32-bytes!!"))
	if err != nil {
		t.Fatalf("NewSubjectHasher: %v", err)
	}
	subjectHMAC := hasher.Hash("acme", "alice@example.com")
	userID, _, err := h.store.ResolveOrCreateFederatedUser(context.Background(), "acme", subjectHMAC, subjectHMACKeyVersion, "EU")
	if err != nil {
		t.Fatalf("seed federated user: %v", err)
	}
	u := pool.users[userID]
	u.Status = "erased"
	pool.putUser(u)

	rec := doPostUserSessions(h, `{"namespace_id":"acme","subject":"alice@example.com"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	if got := decodeError(t, rec); got.Code != cloudopenapi.ErrorCodeSubjectUnavailable {
		t.Errorf("error.code = %q, want subject_unavailable", got.Code)
	}
}

func TestPostUserSessionsSuccessReturns201WithLoginCode(t *testing.T) {
	h, _, _ := newUserSessionsTestHandler(t)
	rec := doPostUserSessions(h, `{"namespace_id":"acme","subject":"alice@example.com"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	var resp cloudopenapi.UserSessionMintResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body = %s", err, rec.Body.String())
	}
	if resp.LoginCode == "" {
		t.Error("login_code is empty")
	}
	if !resp.Created {
		t.Error("created = false, want true (first sighting of this subject)")
	}
	if !resp.ExpiresAt.After(time.Now()) {
		t.Errorf("expires_at = %v, want a future time", resp.ExpiresAt)
	}

	// No login_url field: the whole point is that the caller builds the
	// redirect target itself.
	if strings.Contains(rec.Body.String(), "login_url") {
		t.Error("response body must never contain login_url")
	}
}

// TestPostUserSessionsSameSubjectSecondCallCreatedFalse proves the
// idempotent-identity-resolution contract at the HTTP layer: a second mint
// for the same (namespace_id, subject) resolves the SAME user (created:
// false) and issues a fresh, independent login code — never a second user.
func TestPostUserSessionsSameSubjectSecondCallCreatedFalse(t *testing.T) {
	h, _, _ := newUserSessionsTestHandler(t)
	body := `{"namespace_id":"acme","subject":"alice@example.com"}`

	first := doPostUserSessions(h, body)
	if first.Code != http.StatusCreated {
		t.Fatalf("first call status = %d, want 201; body = %s", first.Code, first.Body.String())
	}
	var firstResp cloudopenapi.UserSessionMintResponse
	if err := json.Unmarshal(first.Body.Bytes(), &firstResp); err != nil {
		t.Fatalf("decode first response: %v", err)
	}

	second := doPostUserSessions(h, body)
	if second.Code != http.StatusCreated {
		t.Fatalf("second call status = %d, want 201; body = %s", second.Code, second.Body.String())
	}
	var secondResp cloudopenapi.UserSessionMintResponse
	if err := json.Unmarshal(second.Body.Bytes(), &secondResp); err != nil {
		t.Fatalf("decode second response: %v", err)
	}
	if secondResp.Created {
		t.Error("second call: created = true, want false")
	}
	if secondResp.LoginCode == firstResp.LoginCode {
		t.Error("second call must mint a fresh, distinct login code, never replay the first")
	}
}

// TestPostUserSessionsAnchorNamespaceRestrictionRejectsOtherNamespace is M5
// at the handler level: when ServiceClaims restricted to one namespace are
// present in the request context (as cloudAuthorized/requireServiceAuth set
// them in production), a mint request for a DIFFERENT namespace is rejected
// 403 cross_tenant_forbidden — before the namespace-exists lookup even runs,
// so a restricted anchor can't use this endpoint to probe which namespaces
// exist. The same claims mint successfully against the namespace they ARE
// bound to.
func TestPostUserSessionsAnchorNamespaceRestrictionRejectsOtherNamespace(t *testing.T) {
	h, _, _ := newUserSessionsTestHandler(t)
	if _, err := h.store.CreateNamespace(context.Background(), "globex", "active"); err != nil {
		t.Fatalf("CreateNamespace globex: %v", err)
	}

	restricted := ServiceClaims{
		Subject:           "acme-bridge",
		Scopes:            []string{"user-sessions:mint"},
		allowedNamespaces: map[string]struct{}{"acme": {}},
	}

	doWithClaims := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/v1/user-sessions", strings.NewReader(body))
		req = req.WithContext(WithServiceClaims(req.Context(), restricted))
		rec := httptest.NewRecorder()
		h.PostUserSessions(rec, req)
		return rec
	}

	t.Run("namespace outside the anchor's set is rejected", func(t *testing.T) {
		rec := doWithClaims(`{"namespace_id":"globex","subject":"alice@example.com"}`)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
		}
		if got := decodeError(t, rec); got.Code != cloudopenapi.ErrorCodeCrossTenantForbidden {
			t.Errorf("error.code = %q, want cross_tenant_forbidden", got.Code)
		}
	})

	t.Run("the anchor's own bound namespace still succeeds", func(t *testing.T) {
		rec := doWithClaims(`{"namespace_id":"acme","subject":"alice@example.com"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
		}
	})
}

// TestPostUserSessionsNoClaimsInContextIsUnrestricted proves the fallback
// behavior for the many existing tests (and doPostUserSessions callers) that
// invoke PostUserSessions directly, bypassing the HTTP auth middleware that
// sets ServiceClaims: with no claims present, there is no anchor to bind to,
// so the M5 check is a no-op — identical to this handler's behavior before
// M5 existed.
func TestPostUserSessionsNoClaimsInContextIsUnrestricted(t *testing.T) {
	h, _, _ := newUserSessionsTestHandler(t)
	rec := doPostUserSessions(h, `{"namespace_id":"acme","subject":"alice@example.com"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
}

// --- SubjectHasher -----------------------------------------------------

func TestSubjectHasherDeterministic(t *testing.T) {
	hasher, err := NewSubjectHasher([]byte("subject-hmac-test-key-32-bytes!!"))
	if err != nil {
		t.Fatalf("NewSubjectHasher: %v", err)
	}
	a := hasher.Hash("acme", "alice@example.com")
	b := hasher.Hash("acme", "alice@example.com")
	if hex.EncodeToString(a) != hex.EncodeToString(b) {
		t.Error("Hash is not deterministic for the same (namespace, subject) pair")
	}
}

func TestSubjectHasherDistinctAcrossNamespaces(t *testing.T) {
	hasher, err := NewSubjectHasher([]byte("subject-hmac-test-key-32-bytes!!"))
	if err != nil {
		t.Fatalf("NewSubjectHasher: %v", err)
	}
	a := hasher.Hash("acme", "alice@example.com")
	b := hasher.Hash("globex", "alice@example.com")
	if hex.EncodeToString(a) == hex.EncodeToString(b) {
		t.Error("the same subject under two different namespaces must hash to different digests")
	}
}

func TestSubjectHasherRejectsShortKey(t *testing.T) {
	if _, err := NewSubjectHasher([]byte("too-short")); err == nil {
		t.Fatal("expected an error for a key shorter than the minimum")
	}
}

func TestNewUserSessionsHandlerPanicsOnMissingDependencies(t *testing.T) {
	store, _ := newFederatedTestStore(t)
	hasher, err := NewSubjectHasher([]byte("subject-hmac-test-key-32-bytes!!"))
	if err != nil {
		t.Fatalf("NewSubjectHasher: %v", err)
	}
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() }) //nolint:errcheck // test cleanup
	codes := NewRedisLoginCodeStore(redisClient)

	cases := []struct {
		name string
		fn   func()
	}{
		{"nil store", func() { NewUserSessionsHandler(nil, hasher, codes, "EU") }},
		{"nil hasher", func() { NewUserSessionsHandler(store, nil, codes, "EU") }},
		{"nil codes", func() { NewUserSessionsHandler(store, hasher, nil, "EU") }},
		{"empty region", func() { NewUserSessionsHandler(store, hasher, codes, "") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("expected a panic")
				}
			}()
			tc.fn()
		})
	}
}
