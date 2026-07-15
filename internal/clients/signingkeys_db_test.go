package clients

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor/harbor/internal/gen/db"
)

// These are integration-style tests for DBSigningKeyStore (docs/DESIGN.md §7.3).
//
// They drive the store through a stateful fake querier that faithfully emulates
// the semantics of the real signing_keys Postgres table so the store's
// domain⇄sqlc conversion, error mapping, and lifecycle handling are exercised
// exactly as they would be against Postgres:
//
//   - CreateSigningKey inserts in 'pending' state, stamps created_at, and
//     rejects a duplicate kid (the table's UNIQUE(kid) constraint) or duplicate
//     id (primary key).
//   - Lookups that find no row return pgx.ErrNoRows, which the store must map to
//     ErrSigningKeyNotFound.
//   - UpdateSigningKeyState uses COALESCE semantics: a NULL (invalid) timestamp
//     param leaves the existing column untouched, so retiring an active key
//     preserves its promoted_at.
//   - RetireSigningKey flips state→retired and stamps retired_at by kid.
//
// The fake is mutex-guarded so the concurrent-Create test is meaningful under
// `go test -race`. Pointing these tests at a live Postgres is a drop-in swap of
// the querier for a sqlc *db.Queries backed by a pgx pool.

// fakeSigningKeyQuerier is a concurrency-safe in-memory signingKeyQuerier that
// emulates the real signing_keys table semantics for DBSigningKeyStore tests.
type fakeSigningKeyQuerier struct {
	mu   sync.Mutex
	rows map[string]db.SigningKey // keyed by uuidToString(id)
	base time.Time                // base time for deterministic, increasing created_at
	seq  int64                    // monotonic sequence for created_at / retired_at
	err  error                    // if non-nil, Create returns it (DB-failure path)
}

func newFakeSigningKeyQuerier() *fakeSigningKeyQuerier {
	return &fakeSigningKeyQuerier{
		rows: make(map[string]db.SigningKey),
		base: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// nextTS returns a strictly increasing timestamp so created_at ordering is
// deterministic. Caller must hold f.mu.
func (f *fakeSigningKeyQuerier) nextTS() pgtype.Timestamptz {
	f.seq++
	return pgtype.Timestamptz{Time: f.base.Add(time.Duration(f.seq) * time.Millisecond), Valid: true}
}

func (f *fakeSigningKeyQuerier) CreateSigningKey(_ context.Context, arg db.CreateSigningKeyParams) (db.SigningKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return db.SigningKey{}, f.err
	}
	idStr := uuidToString(arg.ID)
	if _, ok := f.rows[idStr]; ok {
		return db.SigningKey{}, fmt.Errorf("signing_keys_pkey: duplicate id %q", idStr)
	}
	for _, r := range f.rows {
		if r.Kid == arg.Kid {
			return db.SigningKey{}, fmt.Errorf("signing_keys_kid_key: duplicate kid %q", arg.Kid)
		}
	}
	row := db.SigningKey{
		ID:                arg.ID,
		Kid:               arg.Kid,
		State:             "pending",
		PublicKeyBytes:    arg.PublicKeyBytes,
		PrivateKeyWrapped: arg.PrivateKeyWrapped,
		Region:            arg.Region,
		CreatedAt:         f.nextTS(),
	}
	f.rows[idStr] = row
	return row, nil
}

func (f *fakeSigningKeyQuerier) GetSigningKeyByKid(_ context.Context, kid string) (db.SigningKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.rows {
		if r.Kid == kid {
			return r, nil
		}
	}
	return db.SigningKey{}, pgx.ErrNoRows
}

func (f *fakeSigningKeyQuerier) GetActiveSigningKey(_ context.Context) (db.SigningKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.rows {
		if r.State == "active" {
			return r, nil
		}
	}
	return db.SigningKey{}, pgx.ErrNoRows
}

func (f *fakeSigningKeyQuerier) ListLiveSigningKeys(_ context.Context) ([]db.SigningKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []db.SigningKey
	for _, r := range f.rows {
		if r.State == "pending" || r.State == "active" {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Time.Equal(out[j].CreatedAt.Time) {
			return out[i].Kid < out[j].Kid
		}
		return out[i].CreatedAt.Time.Before(out[j].CreatedAt.Time)
	})
	return out, nil
}

func (f *fakeSigningKeyQuerier) UpdateSigningKeyState(_ context.Context, arg db.UpdateSigningKeyStateParams) (db.SigningKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idStr := uuidToString(arg.ID)
	r, ok := f.rows[idStr]
	if !ok {
		return db.SigningKey{}, pgx.ErrNoRows
	}
	r.State = arg.State
	// COALESCE semantics: only overwrite when the param is non-NULL (Valid).
	if arg.PromotedAt.Valid {
		r.PromotedAt = arg.PromotedAt
	}
	if arg.RetiredAt.Valid {
		r.RetiredAt = arg.RetiredAt
	}
	f.rows[idStr] = r
	return r, nil
}

func (f *fakeSigningKeyQuerier) RetireSigningKey(_ context.Context, kid string) (db.SigningKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, r := range f.rows {
		if r.Kid == kid {
			r.State = "retired"
			r.RetiredAt = f.nextTS()
			f.rows[id] = r
			return r, nil
		}
	}
	return db.SigningKey{}, pgx.ErrNoRows
}

// --- helpers ----------------------------------------------------------------

// newDBStoreWithFake returns a DBSigningKeyStore backed by a fresh fake querier.
func newDBStoreWithFake() (*DBSigningKeyStore, *fakeSigningKeyQuerier) {
	q := newFakeSigningKeyQuerier()
	return NewDBSigningKeyStore(q), q
}

// newDBTestKey builds a NewSigningKey with a fresh, valid UUID id (the DB store
// scans id into pgtype.UUID, so ids must be real UUIDs).
func newDBTestKey(kid string) NewSigningKey {
	return NewSigningKey{
		ID:                uuid.NewString(),
		Kid:               kid,
		PublicKeyBytes:    []byte("pub-" + kid),
		PrivateKeyWrapped: []byte("wrapped-" + kid),
		Region:            "eu-1",
	}
}

// --- tests ------------------------------------------------------------------

func TestDBSigningKeyStoreImplementsInterface(t *testing.T) {
	var _ SigningKeyStore = (*DBSigningKeyStore)(nil)
}

func TestDBSigningKeyStoreCreateAndGetByKid(t *testing.T) {
	ctx := context.Background()
	s, _ := newDBStoreWithFake()

	created, err := s.Create(ctx, newDBTestKey("kid-a"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.State != "pending" {
		t.Errorf("State: got %q, want pending", created.State)
	}
	if created.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set by the DB")
	}
	if created.PromotedAt != nil || created.RetiredAt != nil {
		t.Error("new key should have nil PromotedAt/RetiredAt")
	}
	if string(created.PublicKeyBytes) != "pub-kid-a" {
		t.Errorf("PublicKeyBytes not preserved: got %q", created.PublicKeyBytes)
	}
	if string(created.PrivateKeyWrapped) != "wrapped-kid-a" {
		t.Errorf("PrivateKeyWrapped not preserved: got %q", created.PrivateKeyWrapped)
	}
	if created.Region != "eu-1" {
		t.Errorf("Region: got %q, want eu-1", created.Region)
	}

	got, err := s.GetByKid(ctx, "kid-a")
	if err != nil {
		t.Fatalf("GetByKid: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("GetByKid ID: got %q, want %q", got.ID, created.ID)
	}
}

func TestDBSigningKeyStoreCreateInvalidUUID(t *testing.T) {
	s, _ := newDBStoreWithFake()
	key := newDBTestKey("kid-a")
	key.ID = "not-a-uuid"
	if _, err := s.Create(context.Background(), key); err == nil {
		t.Error("expected error for invalid UUID id")
	}
}

func TestDBSigningKeyStoreCreateDuplicateKid(t *testing.T) {
	ctx := context.Background()
	s, _ := newDBStoreWithFake()
	if _, err := s.Create(ctx, newDBTestKey("dup")); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if _, err := s.Create(ctx, newDBTestKey("dup")); err == nil {
		t.Error("expected error creating key with duplicate kid (UNIQUE(kid))")
	}
}

func TestDBSigningKeyStoreCreateDBError(t *testing.T) {
	s, q := newDBStoreWithFake()
	q.err = errors.New("connection refused")
	if _, err := s.Create(context.Background(), newDBTestKey("kid-a")); err == nil {
		t.Error("expected DB error to propagate from Create")
	}
}

func TestDBSigningKeyStoreGetByKidNotFound(t *testing.T) {
	s, _ := newDBStoreWithFake()
	_, err := s.GetByKid(context.Background(), "missing")
	if !errors.Is(err, ErrSigningKeyNotFound) {
		t.Errorf("expected ErrSigningKeyNotFound, got %v", err)
	}
}

func TestDBSigningKeyStoreGetActiveNotFound(t *testing.T) {
	ctx := context.Background()
	s, _ := newDBStoreWithFake()
	// Only a pending key exists → no active key.
	if _, err := s.Create(ctx, newDBTestKey("kid-a")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.GetActive(ctx); !errors.Is(err, ErrSigningKeyNotFound) {
		t.Errorf("expected ErrSigningKeyNotFound, got %v", err)
	}
}

func TestDBSigningKeyStoreSetStateNotFound(t *testing.T) {
	s, _ := newDBStoreWithFake()
	_, err := s.SetState(context.Background(), uuid.NewString(), "active", nil, nil)
	if !errors.Is(err, ErrSigningKeyNotFound) {
		t.Errorf("expected ErrSigningKeyNotFound, got %v", err)
	}
}

func TestDBSigningKeyStoreSetStateInvalidUUID(t *testing.T) {
	s, _ := newDBStoreWithFake()
	if _, err := s.SetState(context.Background(), "not-a-uuid", "active", nil, nil); err == nil {
		t.Error("expected error for invalid UUID id")
	}
}

func TestDBSigningKeyStoreRetireNotFound(t *testing.T) {
	s, _ := newDBStoreWithFake()
	_, err := s.Retire(context.Background(), "missing")
	if !errors.Is(err, ErrSigningKeyNotFound) {
		t.Errorf("expected ErrSigningKeyNotFound, got %v", err)
	}
}

// TestDBSigningKeyStoreStateTransitionsPersist walks a key through the full
// pending → active → retired lifecycle and asserts each transition (and its
// timestamps) persists, including COALESCE preservation of promoted_at when the
// key is later retired via SetState.
func TestDBSigningKeyStoreStateTransitionsPersist(t *testing.T) {
	ctx := context.Background()
	s, _ := newDBStoreWithFake()

	created, err := s.Create(ctx, newDBTestKey("kid-a"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// pending: live, not active.
	if _, err := s.GetActive(ctx); !errors.Is(err, ErrSigningKeyNotFound) {
		t.Errorf("pending: expected no active key, got %v", err)
	}
	if live, _ := s.ListLive(ctx); len(live) != 1 {
		t.Errorf("pending: ListLive got %d, want 1", len(live))
	}

	// Promote to active with a promoted_at timestamp.
	promoted := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if _, err := s.SetState(ctx, created.ID, "active", &promoted, nil); err != nil {
		t.Fatalf("SetState active: %v", err)
	}
	active, err := s.GetActive(ctx)
	if err != nil {
		t.Fatalf("GetActive after promote: %v", err)
	}
	if active.ID != created.ID {
		t.Errorf("active ID: got %q, want %q", active.ID, created.ID)
	}
	if active.PromotedAt == nil || !active.PromotedAt.Equal(promoted) {
		t.Errorf("promoted_at not persisted: got %v, want %v", active.PromotedAt, promoted)
	}

	// Retire via SetState passing ONLY retired_at — promoted_at must be
	// preserved by the COALESCE in UpdateSigningKeyState.
	retired := promoted.Add(15 * time.Minute)
	got, err := s.SetState(ctx, created.ID, "retired", nil, &retired)
	if err != nil {
		t.Fatalf("SetState retired: %v", err)
	}
	if got.PromotedAt == nil || !got.PromotedAt.Equal(promoted) {
		t.Errorf("promoted_at not preserved on retire: got %v, want %v", got.PromotedAt, promoted)
	}
	if got.RetiredAt == nil || !got.RetiredAt.Equal(retired) {
		t.Errorf("retired_at not persisted: got %v, want %v", got.RetiredAt, retired)
	}

	// After retirement: no active key, excluded from ListLive, still findable.
	if _, err := s.GetActive(ctx); !errors.Is(err, ErrSigningKeyNotFound) {
		t.Errorf("retired: expected no active key, got %v", err)
	}
	if live, _ := s.ListLive(ctx); len(live) != 0 {
		t.Errorf("retired: ListLive got %d, want 0", len(live))
	}
	if _, err := s.GetByKid(ctx, "kid-a"); err != nil {
		t.Errorf("GetByKid on retired key: %v", err)
	}
}

// TestDBSigningKeyStoreRetireByKid verifies the Retire path (used by emergency
// rotation) flips state and stamps retired_at.
func TestDBSigningKeyStoreRetireByKid(t *testing.T) {
	ctx := context.Background()
	s, _ := newDBStoreWithFake()
	created, err := s.Create(ctx, newDBTestKey("kid-a"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.Retire(ctx, created.Kid)
	if err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if got.State != "retired" {
		t.Errorf("State: got %q, want retired", got.State)
	}
	if got.RetiredAt == nil {
		t.Error("retired_at should be stamped by Retire")
	}
	if live, _ := s.ListLive(ctx); len(live) != 0 {
		t.Errorf("ListLive after retire: got %d, want 0", len(live))
	}
}

// TestDBSigningKeyStoreListLiveOrdering verifies ListLive returns pending +
// active keys (retired excluded) in created_at order.
func TestDBSigningKeyStoreListLiveOrdering(t *testing.T) {
	ctx := context.Background()
	s, _ := newDBStoreWithFake()

	k1, _ := s.Create(ctx, newDBTestKey("kid-1"))
	k2, _ := s.Create(ctx, newDBTestKey("kid-2"))
	k3, _ := s.Create(ctx, newDBTestKey("kid-3"))

	// Promote k2, retire k3, leave k1 pending.
	promoted := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if _, err := s.SetState(ctx, k2.ID, "active", &promoted, nil); err != nil {
		t.Fatalf("SetState active: %v", err)
	}
	if _, err := s.Retire(ctx, k3.Kid); err != nil {
		t.Fatalf("Retire: %v", err)
	}

	live, err := s.ListLive(ctx)
	if err != nil {
		t.Fatalf("ListLive: %v", err)
	}
	if len(live) != 2 {
		t.Fatalf("ListLive len: got %d, want 2 (retired excluded)", len(live))
	}
	// created_at order: k1 (pending) then k2 (active).
	if live[0].Kid != k1.Kid || live[1].Kid != k2.Kid {
		t.Errorf("ListLive order: got [%s, %s], want [%s, %s]", live[0].Kid, live[1].Kid, k1.Kid, k2.Kid)
	}
}

// TestDBSigningKeyStoreConcurrentCreate issues many Create calls concurrently
// (distinct ids + kids) and verifies they all persist with no lost updates,
// data races (run under -race), or duplicate-kid false positives.
func TestDBSigningKeyStoreConcurrentCreate(t *testing.T) {
	ctx := context.Background()
	s, _ := newDBStoreWithFake()

	const n = 32
	var wg sync.WaitGroup
	wg.Add(n)
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			kid := fmt.Sprintf("kid-%02d", i)
			if _, err := s.Create(ctx, newDBTestKey(kid)); err != nil {
				errCh <- fmt.Errorf("Create %s: %w", kid, err)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	// All n keys are pending → all live.
	live, err := s.ListLive(ctx)
	if err != nil {
		t.Fatalf("ListLive: %v", err)
	}
	if len(live) != n {
		t.Errorf("ListLive len: got %d, want %d", len(live), n)
	}
}
