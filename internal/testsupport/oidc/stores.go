// Package oidctest provides OIDC collaborators for tests outside internal/oidc.
package oidctest

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"sync"
	"time"

	harboroidc "github.com/harbor-auth/harbor/internal/oidc"
)

// InMemoryClientRegistry is a dev/test harboroidc.ClientRegistry. NOT for production.
type InMemoryClientRegistry struct {
	mu      sync.RWMutex
	clients map[string]harboroidc.Client
}

// NewInMemoryClientRegistry returns an empty registry.
func NewInMemoryClientRegistry() *InMemoryClientRegistry {
	return &InMemoryClientRegistry{clients: make(map[string]harboroidc.Client)}
}

// Put seeds or replaces a client registration.
func (r *InMemoryClientRegistry) Put(c harboroidc.Client) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients[c.ID] = c
}

// Delete removes a client registration by ID. A no-op if the client was not
// registered. Used in tests to simulate deregistration of a client.
func (r *InMemoryClientRegistry) Delete(clientID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.clients, clientID)
}

// Lookup implements harboroidc.ClientRegistry.
func (r *InMemoryClientRegistry) Lookup(_ context.Context, clientID string) (harboroidc.Client, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.clients[clientID]
	return c, ok
}

type authCodeEntry struct {
	code     harboroidc.AuthCode
	consumed bool
}

// InMemoryAuthCodeStore is a dev/test harboroidc.AuthCodeStore. NOT for production — a real
// store is region-local and shared across replicas (e.g. Redis; docs/DESIGN.md
// §4.4) with its own TTL eviction.
type InMemoryAuthCodeStore struct {
	mu    sync.Mutex
	codes map[string]*authCodeEntry
}

// NewInMemoryAuthCodeStore returns an empty code store.
func NewInMemoryAuthCodeStore() *InMemoryAuthCodeStore {
	return &InMemoryAuthCodeStore{codes: make(map[string]*authCodeEntry)}
}

// Save implements harboroidc.AuthCodeStore.
func (s *InMemoryAuthCodeStore) Save(_ context.Context, code harboroidc.AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code.Code] = &authCodeEntry{code: code}
	return nil
}

// Peek implements harboroidc.AuthCodeStore: reads the stored code and its consumed state
// without mutating it.
func (s *InMemoryAuthCodeStore) Peek(_ context.Context, code string) (harboroidc.AuthCode, bool, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.codes[code]
	if !ok {
		return harboroidc.AuthCode{}, false, false, nil
	}
	return entry.code, true, entry.consumed, nil
}

// Consume implements harboroidc.AuthCodeStore with reuse detection: the first call returns
// harboroidc.ConsumeFirstUse and tombstones the entry; any later call returns
// harboroidc.ConsumeReused.
func (s *InMemoryAuthCodeStore) Consume(_ context.Context, code string) (harboroidc.ConsumeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.codes[code]
	if !ok {
		return harboroidc.ConsumeResult{Status: harboroidc.ConsumeNotFound}, nil
	}
	if entry.consumed {
		return harboroidc.ConsumeResult{Status: harboroidc.ConsumeReused, Code: entry.code}, nil
	}
	entry.consumed = true
	return harboroidc.ConsumeResult{Status: harboroidc.ConsumeFirstUse, Code: entry.code}, nil
}

// sessionEntry is a stored session plus its revoked flag (in-memory store).
type sessionEntry struct {
	s       harboroidc.RefreshSession
	revoked bool
}

// InMemorySessionStore is a dev/test harboroidc.SessionStore. NOT for production — a real
// store persists sessions durably (internal/clients.DBSessionStore).
//
// Time: expiry checks use time.Now() directly (wall-clock), not an injectable
// clock. Use ForceExpireAllForTest() to fast-forward expiry in tests rather
// than sleeping. A future refactor could inject a clock via the constructor, but
// the current test-helper approach is sufficient for the existing test surface.
type InMemorySessionStore struct {
	mu     sync.Mutex
	byID   map[string]*sessionEntry
	byHash map[string]*sessionEntry // key: base64url(sha256(token))
}

// NewInMemorySessionStore returns an empty store.
func NewInMemorySessionStore() *InMemorySessionStore {
	return &InMemorySessionStore{
		byID:   make(map[string]*sessionEntry),
		byHash: make(map[string]*sessionEntry),
	}
}

// CreateSession implements harboroidc.SessionStore.
func (s *InMemorySessionStore) CreateSession(_ context.Context, rs harboroidc.RefreshSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := &sessionEntry{s: rs}
	s.byID[rs.ID] = entry
	s.byHash[base64.RawURLEncoding.EncodeToString(rs.TokenHash)] = entry
	return nil
}

// GetSessionByTokenHash implements harboroidc.SessionStore.
func (s *InMemorySessionStore) GetSessionByTokenHash(_ context.Context, hash []byte) (harboroidc.RefreshSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := base64.RawURLEncoding.EncodeToString(hash)
	entry, ok := s.byHash[key]
	if !ok {
		return harboroidc.RefreshSession{}, harboroidc.ErrRefreshTokenNotFound
	}
	if entry.revoked {
		return entry.s, harboroidc.ErrRefreshTokenRevoked
	}
	if time.Now().After(entry.s.ExpiresAt) {
		return harboroidc.RefreshSession{}, harboroidc.ErrRefreshTokenNotFound
	}
	return entry.s, nil
}

// RevokeSession implements harboroidc.SessionStore.
func (s *InMemorySessionStore) RevokeSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.byID[id]; ok {
		e.revoked = true
		e.s.RevokedAt = time.Now()
	}
	return nil
}

// RotateSession implements harboroidc.SessionStore. Revoke + create happen under a single
// lock acquisition, so there is no crash window between them.
func (s *InMemorySessionStore) RotateSession(_ context.Context, oldID string, newSession harboroidc.RefreshSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Compare-and-swap the old session. A concurrent replica that observed the
	// token before the winner rotated it must not mint a second successor.
	e, ok := s.byID[oldID]
	if !ok || e.revoked || !time.Now().Before(e.s.ExpiresAt) {
		return harboroidc.ErrRefreshTokenRevoked
	}
	e.revoked = true
	e.s.RevokedAt = time.Now()
	// Create new.
	entry := &sessionEntry{s: newSession}
	s.byID[newSession.ID] = entry
	s.byHash[base64.RawURLEncoding.EncodeToString(newSession.TokenHash)] = entry
	return nil
}

// ForceExpireAllForTest immediately back-dates every active session's ExpiresAt
// to one second in the past, simulating TTL expiry without sleeping.
// For use in tests only — not called from production code paths.
//
// NOTE: This method intentionally lives in non-test code (not export_test.go)
// because internal/oidcapi tests call it cross-package on a *InMemorySessionStore
// value imported from internal/oidc. Moving it to export_test.go would make it
// invisible to external test packages (Go test exports are intra-package only)
// without introducing a separate testutil package. Accept as a test-helper
// with a sufficiently obvious name to prevent accidental production use.
func (s *InMemorySessionStore) ForceExpireAllForTest() {
	s.mu.Lock()
	defer s.mu.Unlock()
	past := time.Now().Add(-time.Second)
	for _, e := range s.byID {
		if !e.revoked {
			e.s.ExpiresAt = past
		}
	}
}

// RevokeSessionsByUserClient implements harboroidc.SessionStore (theft signal family revoke).
func (s *InMemorySessionStore) RevokeSessionsByUserClient(_ context.Context, userID, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.byID {
		if e.s.UserID == userID && e.s.ClientID == clientID {
			e.revoked = true
			e.s.RevokedAt = time.Now()
		}
	}
	return nil
}

// RevokeSessionsByGrant implements harboroidc.SessionStore (per-grant revoke for §11.3 disconnect flow).
func (s *InMemorySessionStore) RevokeSessionsByGrant(_ context.Context, grantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.byID {
		if e.s.GrantID == grantID {
			e.revoked = true
			e.s.RevokedAt = time.Now()
		}
	}
	return nil
}

// InMemoryGrantStore is a dev/test harboroidc.GrantStore. NOT for production — a real store
// persists grants durably so they survive restarts (internal/clients.DBGrantStore).
type InMemoryGrantStore struct {
	mu      sync.Mutex
	byID    map[string]*harboroidc.Grant
	byPair  map[string]*harboroidc.Grant // key: userID+":"+clientID
	counter int                          // monotonically increasing; never decrements so IDs stay unique even if grants were deleted
}

// NewInMemoryGrantStore returns an empty in-memory grant store.
func NewInMemoryGrantStore() *InMemoryGrantStore {
	return &InMemoryGrantStore{
		byID:   make(map[string]*harboroidc.Grant),
		byPair: make(map[string]*harboroidc.Grant),
	}
}

// FindGrant implements harboroidc.GrantStore. Returns only active (non-revoked) grants.
func (s *InMemoryGrantStore) FindGrant(_ context.Context, userID, clientID string) (harboroidc.Grant, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byPair[userID+":"+clientID]
	if !ok || g.RevokedAt != nil {
		return harboroidc.Grant{}, false, nil
	}
	// Clone Scopes so that caller mutation of the returned slice cannot corrupt
	// the stored *harboroidc.Grant. Append-only callers are safe without a clone, but
	// index-based mutation (out.Scopes[0] = "evil") would silently modify the
	// stored grant without a copy.
	out := *g
	out.Scopes = append([]string(nil), g.Scopes...)
	return out, true, nil
}

// FindGrantByPPID implements harboroidc.GrantStore. Searches by pairwise_sub (PPID) and
// clientID for reverse-lookup during RP-Initiated Logout.
func (s *InMemoryGrantStore) FindGrantByPPID(_ context.Context, ppid, clientID string) (harboroidc.Grant, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.byID {
		if g.PairwiseSub == ppid && g.ClientID == clientID && g.RevokedAt == nil {
			out := *g
			out.Scopes = append([]string(nil), g.Scopes...)
			return out, true, nil
		}
	}
	return harboroidc.Grant{}, false, nil
}

// CreateGrant implements harboroidc.GrantStore. Mints a sequential string ID.
// If an active grant already exists for the (userID, clientID) pair, it is
// soft-deleted before the new one is created — mirroring the DB UNIQUE index
// semantics on (user_id, client_id) for active grants. Without this, the old
// pointer in byID would become orphaned (FindGrant via byPair would shadow it,
// but ListGrantsByUser via byID would not, producing inconsistent results).
func (s *InMemoryGrantStore) CreateGrant(_ context.Context, ng harboroidc.NewGrant) (harboroidc.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Soft-delete any existing ACTIVE grant for this (user, client) pair so byID
	// and byPair stay consistent. Only revoke if RevokedAt is nil — byPair can
	// already point to a previously revoked grant (RevokeGrant mutates the shared
	// pointer but does not clear byPair).
	if existing, ok := s.byPair[ng.UserID+":"+ng.ClientID]; ok && existing.RevokedAt == nil {
		now := time.Now()
		existing.RevokedAt = &now
	}
	// id is a zero-padded monotonically-increasing sequence. Zero-padding
	// (8 digits) ensures lexicographic sort order matches numeric order for up
	// to 99_999_999 grants — required for the ListGrantsByUser ID tiebreaker.
	// Using a dedicated counter (not len(byID)) means IDs stay unique even if a
	// Delete method is ever added.
	s.counter++
	id := fmt.Sprintf("grant-%08d", s.counter)
	g := &harboroidc.Grant{
		ID:          id,
		Region:      ng.Region,
		UserID:      ng.UserID,
		ClientID:    ng.ClientID,
		PairwiseSub: ng.PairwiseSub,
		Scopes:      append([]string(nil), ng.Scopes...), // Clone 1: prevents ng.Scopes mutations from corrupting the stored grant
		CreatedAt:   time.Now(),
	}
	s.byID[id] = g
	s.byPair[ng.UserID+":"+ng.ClientID] = g
	// Clone 2: ret := *g copies the harboroidc.Grant struct by value, including the Scopes
	// slice header — ret.Scopes and g.Scopes would share the same backing array.
	// Index-mutation by the caller (ret.Scopes[0] = "evil") would silently corrupt
	// the stored grant. Clone 1 (above in g.Scopes initialisation) protected g from
	// ng.Scopes; this clone protects g from the returned ret.Scopes.
	ret := *g
	ret.Scopes = append([]string(nil), g.Scopes...)
	return ret, nil
}

// RevokeGrant implements harboroidc.GrantStore. Soft-deletes by ID.
func (s *InMemoryGrantStore) RevokeGrant(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byID[id]
	if !ok {
		return nil // idempotent
	}
	now := time.Now()
	g.RevokedAt = &now
	return nil
}

// UpdateGrantScopes implements harboroidc.GrantScopeUpdater.
func (s *InMemoryGrantStore) UpdateGrantScopes(_ context.Context, userID, clientID string, scopes []string) (harboroidc.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byPair[userID+":"+clientID]
	if !ok || g.RevokedAt != nil {
		return harboroidc.Grant{}, fmt.Errorf("oidc: active grant not found")
	}
	g.Scopes = append([]string(nil), scopes...)
	out := *g
	out.Scopes = append([]string(nil), g.Scopes...)
	return out, nil
}

// RevokeGrantAndSessions implements harboroidc.GrantDisconnector. The in-memory grant
// store has no independent session collection; InMemorySessionStore owns the
// corresponding dev/test atomic implementation when assembled flows need it.
func (s *InMemoryGrantStore) RevokeGrantAndSessions(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byID[id]
	if !ok || g.RevokedAt != nil {
		return false, nil
	}
	now := time.Now()
	g.RevokedAt = &now
	return true, nil
}

// ListGrantsByUser implements harboroidc.GrantStore. Returns only active (non-revoked) grants.
func (s *InMemoryGrantStore) ListGrantsByUser(_ context.Context, userID string) ([]harboroidc.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []harboroidc.Grant
	for _, g := range s.byID {
		if g.UserID == userID && g.RevokedAt == nil {
			// Clone Scopes for consistency with FindGrant: caller mutation of the
			// returned slice must not corrupt the stored grant.
			gc := *g
			gc.Scopes = append([]string(nil), g.Scopes...)
			out = append(out, gc)
		}
	}
	// Sort newest first to match the interface contract and DBGrantStore
	// ordering. byID iteration order is non-deterministic (Go map), so without
	// this the "connected apps" dashboard order would be unstable.
	// Tiebreaker on ID (lexicographic descending) stabilises the sort when two
	// grants share the same CreatedAt timestamp (possible in fast-running tests
	// where time.Now() has millisecond resolution).
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID // later sequential ID = newer grant
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// FixedAuthSource returns a fixed user ID. SCAFFOLD/dev only — replace with the
// real BFF-session-backed harboroidc.AuthSource in production.
type FixedAuthSource struct{ userID string }

// NewFixedAuthSource returns an harboroidc.AuthSource that always authenticates as userID.
func NewFixedAuthSource(userID string) *FixedAuthSource {
	return &FixedAuthSource{userID: userID}
}

// AuthenticatedUserID implements harboroidc.AuthSource.
func (a *FixedAuthSource) AuthenticatedUserID(_ context.Context) (string, error) {
	return a.userID, nil
}

// InMemorySecretLoader is a dev/test harboroidc.UserSecretLoader. NOT for production — a
// real loader decrypts from the users table (internal/clients.DBSecretLoader).
type InMemorySecretLoader struct {
	mu      sync.RWMutex
	secrets map[string]harboroidc.UserSecret
}

// NewInMemorySecretLoader returns an empty loader.
func NewInMemorySecretLoader() *InMemorySecretLoader {
	return &InMemorySecretLoader{secrets: make(map[string]harboroidc.UserSecret)}
}

// Put seeds or replaces the secret for userID.
func (l *InMemorySecretLoader) Put(userID string, us harboroidc.UserSecret) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Clone Secret so a caller that reuses the []byte slice after Put cannot
	// corrupt the stored secret via the shared backing array.
	us.Secret = append([]byte(nil), us.Secret...)
	l.secrets[userID] = us
}

// LoadUserSecret implements harboroidc.UserSecretLoader.
func (l *InMemorySecretLoader) LoadUserSecret(_ context.Context, userID string) (harboroidc.UserSecret, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	us, ok := l.secrets[userID]
	if !ok {
		return harboroidc.UserSecret{}, harboroidc.ErrUserSecretNotFound
	}
	// Clone Secret so the caller cannot corrupt the stored value via the returned slice.
	us.Secret = append([]byte(nil), us.Secret...)
	return us, nil
}

// stubSessionResolver auto-approves a fixed subject. SCAFFOLD only.
type stubSessionResolver struct{ subject string }

// NewStubSessionResolver returns a harboroidc.SessionResolver that always authenticates and
// consents as subject. SCAFFOLD — replace with real passkey login + consent.
func NewStubSessionResolver(subject string) harboroidc.SessionResolver {
	return stubSessionResolver{subject: subject}
}

// Resolve always returns userID="" (empty). This is intentional for unit-test
// simplicity — Token() gates issueRefreshToken on `result.Code.UserID != ""`
// (docs/DESIGN.md §3.5), so any test using stubSessionResolver will NEVER
// receive a refresh token through a full Authorize→Token flow. Use
// PPIDSessionResolver with a FixedAuthSource for refresh-token integration
// tests (see newRefreshFlowServerWithStore in refresh_rotation_test.go).
func (r stubSessionResolver) Resolve(_ context.Context, _ harboroidc.Client, _ string) (string, string, bool, error) {
	return r.subject, "", true, nil
}
