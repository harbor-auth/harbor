package clients

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	db "github.com/harbor/harbor/internal/gen/db"
	"github.com/harbor/harbor/internal/oidc"
)

// fakeConsentEmitter records emitted consent events for assertions.
type fakeConsentEmitter struct {
	events []oidc.ConsentEvent
}

func (f *fakeConsentEmitter) Emit(_ context.Context, e oidc.ConsentEvent) error {
	f.events = append(f.events, e)
	return nil
}

// fakeConsentQuerier implements consentQuerier for unit tests.
type fakeConsentQuerier struct {
	grants map[string]db.ConsentGrant // key: userID+":"+clientID
	byID   map[string]db.ConsentGrant // key: id (UUID string)
}

func newFakeConsentQuerier() *fakeConsentQuerier {
	return &fakeConsentQuerier{
		grants: make(map[string]db.ConsentGrant),
		byID:   make(map[string]db.ConsentGrant),
	}
}

func (f *fakeConsentQuerier) GetConsentGrantByUserClient(_ context.Context, arg db.GetConsentGrantByUserClientParams) (db.ConsentGrant, error) {
	key := arg.UserID.String() + ":" + arg.ClientID
	g, ok := f.grants[key]
	if !ok || g.RevokedAt.Valid {
		return db.ConsentGrant{}, pgx.ErrNoRows
	}
	return g, nil
}

func (f *fakeConsentQuerier) UpsertConsentGrant(_ context.Context, arg db.UpsertConsentGrantParams) (db.ConsentGrant, error) {
	key := arg.UserID.String() + ":" + arg.ClientID
	now := pgtype.Timestamptz{Time: time.Now(), Valid: true}

	// Check for existing active grant
	if existing, ok := f.grants[key]; ok && !existing.RevokedAt.Valid {
		// Update existing
		existing.Scopes = arg.Scopes
		existing.UpdatedAt = now
		f.grants[key] = existing
		f.byID[existing.ID.String()] = existing
		return existing, nil
	}

	// Create new
	var id pgtype.UUID
	if err := id.Scan("11111111-1111-1111-1111-111111111111"); err != nil {
		return db.ConsentGrant{}, err
	}
	g := db.ConsentGrant{
		ID:        id,
		UserID:    arg.UserID,
		ClientID:  arg.ClientID,
		Scopes:    arg.Scopes,
		GrantedAt: now,
		UpdatedAt: now,
	}
	f.grants[key] = g
	f.byID[id.String()] = g
	return g, nil
}

func (f *fakeConsentQuerier) ListConsentGrantsByUser(_ context.Context, userID pgtype.UUID) ([]db.ConsentGrant, error) {
	var out []db.ConsentGrant
	for _, g := range f.grants {
		if g.UserID == userID && !g.RevokedAt.Valid {
			out = append(out, g)
		}
	}
	return out, nil
}

func (f *fakeConsentQuerier) RevokeConsentGrant(_ context.Context, id pgtype.UUID) error {
	idStr := id.String()
	if g, ok := f.byID[idStr]; ok && !g.RevokedAt.Valid {
		g.RevokedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
		f.byID[idStr] = g
		key := g.UserID.String() + ":" + g.ClientID
		f.grants[key] = g
	}
	return nil
}

func TestDBConsentStore_Get_NotFound(t *testing.T) {
	store := NewDBConsentStore(newFakeConsentQuerier())
	ctx := context.Background()

	_, found, err := store.Get(ctx, "550e8400-e29b-41d4-a716-446655440000", "test-client")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Error("expected found=false for non-existent grant")
	}
}

func TestDBConsentStore_Get_InvalidUserID(t *testing.T) {
	store := NewDBConsentStore(newFakeConsentQuerier())
	ctx := context.Background()

	_, _, err := store.Get(ctx, "not-a-uuid", "test-client")
	if err == nil {
		t.Error("expected error for invalid userID")
	}
}

func TestDBConsentStore_UpsertAndGet(t *testing.T) {
	store := NewDBConsentStore(newFakeConsentQuerier())
	ctx := context.Background()
	userID := "550e8400-e29b-41d4-a716-446655440000"
	clientID := "test-client"

	// Upsert creates new grant
	grant, err := store.Upsert(ctx, userID, clientID, []string{"openid", "profile"})
	if err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}
	if grant.ClientID != clientID {
		t.Errorf("ClientID = %q, want %q", grant.ClientID, clientID)
	}
	if len(grant.Scopes) != 2 {
		t.Errorf("Scopes len = %d, want 2", len(grant.Scopes))
	}

	// Get retrieves it
	got, found, err := store.Get(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !found {
		t.Error("expected found=true")
	}
	if got.ClientID != clientID {
		t.Errorf("Get ClientID = %q, want %q", got.ClientID, clientID)
	}
}

func TestDBConsentStore_Upsert_UpdatesExisting(t *testing.T) {
	store := NewDBConsentStore(newFakeConsentQuerier())
	ctx := context.Background()
	userID := "550e8400-e29b-41d4-a716-446655440000"
	clientID := "test-client"

	// Create initial
	_, err := store.Upsert(ctx, userID, clientID, []string{"openid"})
	if err != nil {
		t.Fatalf("first Upsert failed: %v", err)
	}

	// Update with new scopes
	grant, err := store.Upsert(ctx, userID, clientID, []string{"openid", "email", "profile"})
	if err != nil {
		t.Fatalf("second Upsert failed: %v", err)
	}
	// Scopes should be canonicalized (sorted)
	if len(grant.Scopes) != 3 {
		t.Errorf("Scopes len = %d, want 3", len(grant.Scopes))
	}
}

func TestDBConsentStore_Upsert_InvalidUserID(t *testing.T) {
	store := NewDBConsentStore(newFakeConsentQuerier())
	ctx := context.Background()

	_, err := store.Upsert(ctx, "not-a-uuid", "test-client", []string{"openid"})
	if err == nil {
		t.Error("expected error for invalid userID")
	}
}

func TestDBConsentStore_List(t *testing.T) {
	store := NewDBConsentStore(newFakeConsentQuerier())
	ctx := context.Background()
	userID := "550e8400-e29b-41d4-a716-446655440000"

	// Create grants for two clients
	if _, err := store.Upsert(ctx, userID, "client-a", []string{"openid"}); err != nil {
		t.Fatalf("upsert client-a: %v", err)
	}
	if _, err := store.Upsert(ctx, userID, "client-b", []string{"profile"}); err != nil {
		t.Fatalf("upsert client-b: %v", err)
	}

	grants, err := store.List(ctx, userID)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(grants) != 2 {
		t.Errorf("List returned %d grants, want 2", len(grants))
	}
}

func TestDBConsentStore_List_InvalidUserID(t *testing.T) {
	store := NewDBConsentStore(newFakeConsentQuerier())
	ctx := context.Background()

	_, err := store.List(ctx, "not-a-uuid")
	if err == nil {
		t.Error("expected error for invalid userID")
	}
}

func TestDBConsentStore_Revoke(t *testing.T) {
	fake := newFakeConsentQuerier()
	store := NewDBConsentStore(fake)
	ctx := context.Background()
	userID := "550e8400-e29b-41d4-a716-446655440000"
	clientID := "test-client"

	// Create grant
	grant, err := store.Upsert(ctx, userID, clientID, []string{"openid"})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Revoke it
	err = store.Revoke(ctx, grant.ID)
	if err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	// Get should return not found
	_, found, err := store.Get(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("Get after Revoke failed: %v", err)
	}
	if found {
		t.Error("expected found=false after revocation")
	}
}

func TestDBConsentStore_Revoke_InvalidID(t *testing.T) {
	store := NewDBConsentStore(newFakeConsentQuerier())
	ctx := context.Background()

	err := store.Revoke(ctx, "not-a-uuid")
	if err == nil {
		t.Error("expected error for invalid id")
	}
}

func TestDBConsentStore_Upsert_EmitsGrantedEvent(t *testing.T) {
	emitter := &fakeConsentEmitter{}
	store := NewDBConsentStore(newFakeConsentQuerier()).WithEmitter(emitter)
	ctx := context.Background()
	userID := "550e8400-e29b-41d4-a716-446655440000"

	if _, err := store.Upsert(ctx, userID, "client-a", []string{"openid"}); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}

	if len(emitter.events) != 1 {
		t.Fatalf("got %d events, want 1", len(emitter.events))
	}
	e := emitter.events[0]
	if e.Kind != oidc.ConsentEventGranted {
		t.Errorf("event kind = %q, want %q", e.Kind, oidc.ConsentEventGranted)
	}
	if e.ClientID != "client-a" {
		t.Errorf("event ClientID = %q, want %q", e.ClientID, "client-a")
	}
	if len(e.Scopes) != 1 || e.Scopes[0] != "openid" {
		t.Errorf("event Scopes = %v, want [openid]", e.Scopes)
	}
	if e.GrantID == "" {
		t.Error("event GrantID should be populated")
	}
}

func TestDBConsentStore_Upsert_EmitsScopeEscalatedEvent(t *testing.T) {
	emitter := &fakeConsentEmitter{}
	store := NewDBConsentStore(newFakeConsentQuerier()).WithEmitter(emitter)
	ctx := context.Background()
	userID := "550e8400-e29b-41d4-a716-446655440000"

	if _, err := store.Upsert(ctx, userID, "client-a", []string{"openid"}); err != nil {
		t.Fatalf("first Upsert failed: %v", err)
	}
	if _, err := store.Upsert(ctx, userID, "client-a", []string{"openid", "profile"}); err != nil {
		t.Fatalf("second Upsert failed: %v", err)
	}

	if len(emitter.events) != 2 {
		t.Fatalf("got %d events, want 2", len(emitter.events))
	}
	if emitter.events[0].Kind != oidc.ConsentEventGranted {
		t.Errorf("first event kind = %q, want %q", emitter.events[0].Kind, oidc.ConsentEventGranted)
	}
	esc := emitter.events[1]
	if esc.Kind != oidc.ConsentEventScopeEscalated {
		t.Errorf("second event kind = %q, want %q", esc.Kind, oidc.ConsentEventScopeEscalated)
	}
	if len(esc.Scopes) != 2 {
		t.Errorf("escalation event Scopes = %v, want 2 scopes", esc.Scopes)
	}
}

func TestDBConsentStore_Upsert_NoEventOnUnchangedScopes(t *testing.T) {
	emitter := &fakeConsentEmitter{}
	store := NewDBConsentStore(newFakeConsentQuerier()).WithEmitter(emitter)
	ctx := context.Background()
	userID := "550e8400-e29b-41d4-a716-446655440000"

	if _, err := store.Upsert(ctx, userID, "client-a", []string{"openid", "profile"}); err != nil {
		t.Fatalf("first Upsert failed: %v", err)
	}
	// Re-confirm the same scopes (different order) — must not emit a new event.
	if _, err := store.Upsert(ctx, userID, "client-a", []string{"profile", "openid"}); err != nil {
		t.Fatalf("second Upsert failed: %v", err)
	}

	if len(emitter.events) != 1 {
		t.Fatalf("got %d events, want 1 (only the initial granted event)", len(emitter.events))
	}
}

func TestDBConsentStore_Revoke_EmitsRevokedEvent(t *testing.T) {
	emitter := &fakeConsentEmitter{}
	store := NewDBConsentStore(newFakeConsentQuerier()).WithEmitter(emitter)
	ctx := context.Background()
	userID := "550e8400-e29b-41d4-a716-446655440000"

	grant, err := store.Upsert(ctx, userID, "client-a", []string{"openid"})
	if err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}
	if err := store.Revoke(ctx, grant.ID); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	// Events: granted (from Upsert) + revoked (from Revoke).
	if len(emitter.events) != 2 {
		t.Fatalf("got %d events, want 2", len(emitter.events))
	}
	last := emitter.events[len(emitter.events)-1]
	if last.Kind != oidc.ConsentEventRevoked {
		t.Errorf("last event kind = %q, want %q", last.Kind, oidc.ConsentEventRevoked)
	}
	if last.GrantID != grant.ID {
		t.Errorf("revoked event GrantID = %q, want %q", last.GrantID, grant.ID)
	}
}
