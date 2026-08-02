package oidc

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"sync"
	"time"
)

// InMemoryClientRegistry is a dev/test ClientRegistry. NOT for production.
type InMemoryClientRegistry struct {
	mu      sync.RWMutex
	clients map[string]Client
}

// NewInMemoryClientRegistry returns an empty registry.
func NewInMemoryClientRegistry() *InMemoryClientRegistry {
	return &InMemoryClientRegistry{clients: make(map[string]Client)}
}

// Put seeds or replaces a client registration.
func (r *InMemoryClientRegistry) Put(c Client) {
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

// Lookup implements ClientRegistry.
func (r *InMemoryClientRegistry) Lookup(_ context.Context, clientID string) (Client, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.clients[clientID]
	return c, ok
}

type authCodeEntry struct {
	code     AuthCode
	consumed bool
}

// noopSessionStore is a deliberately inert test double used by corruption and
// revocation-path tests that override only the method under examination.
type noopSessionStore struct{}

func (noopSessionStore) CreateSession(context.Context, RefreshSession) error { return nil }
func (noopSessionStore) GetSessionByTokenHash(context.Context, []byte) (RefreshSession, error) {
	return RefreshSession{}, ErrRefreshTokenNotFound
}
func (noopSessionStore) RevokeSession(context.Context, string) error                 { return nil }
func (noopSessionStore) RotateSession(context.Context, string, RefreshSession) error { return nil }
func (noopSessionStore) RevokeSessionsByUserClient(context.Context, string, string) error {
	return nil
}
func (noopSessionStore) RevokeSessionsByGrant(context.Context, string) error { return nil }

// InMemoryAuthCodeStore is a dev/test AuthCodeStore. NOT for production — a real
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

// Save implements AuthCodeStore.
func (s *InMemoryAuthCodeStore) Save(_ context.Context, code AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code.Code] = &authCodeEntry{code: code}
	return nil
}

// Peek implements AuthCodeStore: reads the stored code and its consumed state
// without mutating it.
func (s *InMemoryAuthCodeStore) Peek(_ context.Context, code string) (AuthCode, bool, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.codes[code]
	if !ok {
		return AuthCode{}, false, false, nil
	}
	return entry.code, true, entry.consumed, nil
}

// Consume implements AuthCodeStore with reuse detection: the first call returns
// ConsumeFirstUse and tombstones the entry; any later call returns
// ConsumeReused.
func (s *InMemoryAuthCodeStore) Consume(_ context.Context, code string) (ConsumeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.codes[code]
	if !ok {
		return ConsumeResult{Status: ConsumeNotFound}, nil
	}
	if entry.consumed {
		return ConsumeResult{Status: ConsumeReused, Code: entry.code}, nil
	}
	entry.consumed = true
	return ConsumeResult{Status: ConsumeFirstUse, Code: entry.code}, nil
}

// sessionEntry is a stored session plus its revoked flag (in-memory store).
type sessionEntry struct {
	s       RefreshSession
	revoked bool
}

// InMemorySessionStore is a dev/test SessionStore. NOT for production — a real
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

// CreateSession implements SessionStore.
func (s *InMemorySessionStore) CreateSession(_ context.Context, rs RefreshSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := &sessionEntry{s: rs}
	s.byID[rs.ID] = entry
	s.byHash[base64.RawURLEncoding.EncodeToString(rs.TokenHash)] = entry
	return nil
}

// GetSessionByTokenHash implements SessionStore.
func (s *InMemorySessionStore) GetSessionByTokenHash(_ context.Context, hash []byte) (RefreshSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := base64.RawURLEncoding.EncodeToString(hash)
	entry, ok := s.byHash[key]
	if !ok {
		return RefreshSession{}, ErrRefreshTokenNotFound
	}
	if entry.revoked {
		return entry.s, ErrRefreshTokenRevoked
	}
	if time.Now().After(entry.s.ExpiresAt) {
		return RefreshSession{}, ErrRefreshTokenNotFound
	}
	return entry.s, nil
}

// RevokeSession implements SessionStore.
func (s *InMemorySessionStore) RevokeSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.byID[id]; ok {
		e.revoked = true
		e.s.RevokedAt = time.Now()
	}
	return nil
}

// RotateSession implements SessionStore. Revoke + create happen under a single
// lock acquisition, so there is no crash window between them.
func (s *InMemorySessionStore) RotateSession(_ context.Context, oldID string, newSession RefreshSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Compare-and-swap the old session. A concurrent replica that observed the
	// token before the winner rotated it must not mint a second successor.
	e, ok := s.byID[oldID]
	if !ok || e.revoked || !time.Now().Before(e.s.ExpiresAt) {
		return ErrRefreshTokenRevoked
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

// RevokeSessionsByUserClient implements SessionStore (theft signal family revoke).
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

// RevokeSessionsByGrant implements SessionStore (per-grant revoke for §11.3 disconnect flow).
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

// InMemoryGrantStore is a dev/test GrantStore. NOT for production — a real store
// persists grants durably so they survive restarts (internal/clients.DBGrantStore).
type InMemoryGrantStore struct {
	mu      sync.Mutex
	byID    map[string]*Grant
	byPair  map[string]*Grant // key: userID+":"+clientID
	counter int               // monotonically increasing; never decrements so IDs stay unique even if grants were deleted
}

// NewInMemoryGrantStore returns an empty in-memory grant store.
func NewInMemoryGrantStore() *InMemoryGrantStore {
	return &InMemoryGrantStore{
		byID:   make(map[string]*Grant),
		byPair: make(map[string]*Grant),
	}
}

// FindGrant implements GrantStore. Returns only active (non-revoked) grants.
func (s *InMemoryGrantStore) FindGrant(_ context.Context, userID, clientID string) (Grant, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byPair[userID+":"+clientID]
	if !ok || g.RevokedAt != nil {
		return Grant{}, false, nil
	}
	// Clone Scopes so that caller mutation of the returned slice cannot corrupt
	// the stored *Grant. Append-only callers are safe without a clone, but
	// index-based mutation (out.Scopes[0] = "evil") would silently modify the
	// stored grant without a copy.
	out := *g
	out.Scopes = append([]string(nil), g.Scopes...)
	return out, true, nil
}

// FindGrantByPPID implements GrantStore. Searches by pairwise_sub (PPID) and
// clientID for reverse-lookup during RP-Initiated Logout.
func (s *InMemoryGrantStore) FindGrantByPPID(_ context.Context, ppid, clientID string) (Grant, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.byID {
		if g.PairwiseSub == ppid && g.ClientID == clientID && g.RevokedAt == nil {
			out := *g
			out.Scopes = append([]string(nil), g.Scopes...)
			return out, true, nil
		}
	}
	return Grant{}, false, nil
}

// CreateGrant implements GrantStore. Mints a sequential string ID.
// If an active grant already exists for the (userID, clientID) pair, it is
// soft-deleted before the new one is created — mirroring the DB UNIQUE index
// semantics on (user_id, client_id) for active grants. Without this, the old
// pointer in byID would become orphaned (FindGrant via byPair would shadow it,
// but ListGrantsByUser via byID would not, producing inconsistent results).
func (s *InMemoryGrantStore) CreateGrant(_ context.Context, ng NewGrant) (Grant, error) {
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
	g := &Grant{
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
	// Clone 2: ret := *g copies the Grant struct by value, including the Scopes
	// slice header — ret.Scopes and g.Scopes would share the same backing array.
	// Index-mutation by the caller (ret.Scopes[0] = "evil") would silently corrupt
	// the stored grant. Clone 1 (above in g.Scopes initialisation) protected g from
	// ng.Scopes; this clone protects g from the returned ret.Scopes.
	ret := *g
	ret.Scopes = append([]string(nil), g.Scopes...)
	return ret, nil
}

// RevokeGrant implements GrantStore. Soft-deletes by ID.
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

// UpdateGrantScopes implements GrantScopeUpdater.
func (s *InMemoryGrantStore) UpdateGrantScopes(_ context.Context, userID, clientID string, scopes []string) (Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byPair[userID+":"+clientID]
	if !ok || g.RevokedAt != nil {
		return Grant{}, fmt.Errorf("oidc: active grant not found")
	}
	g.Scopes = append([]string(nil), scopes...)
	out := *g
	out.Scopes = append([]string(nil), g.Scopes...)
	return out, nil
}

// RevokeGrantAndSessions implements GrantDisconnector. The in-memory grant
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

// ListGrantsByUser implements GrantStore. Returns only active (non-revoked) grants.
func (s *InMemoryGrantStore) ListGrantsByUser(_ context.Context, userID string) ([]Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Grant
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
// real BFF-session-backed AuthSource in production.
type FixedAuthSource struct{ userID string }

// NewFixedAuthSource returns an AuthSource that always authenticates as userID.
func NewFixedAuthSource(userID string) *FixedAuthSource {
	return &FixedAuthSource{userID: userID}
}

// AuthenticatedUserID implements AuthSource.
func (a *FixedAuthSource) AuthenticatedUserID(_ context.Context) (string, error) {
	return a.userID, nil
}

// InMemorySecretLoader is a dev/test UserSecretLoader. NOT for production — a
// real loader decrypts from the users table (internal/clients.DBSecretLoader).
type InMemorySecretLoader struct {
	mu      sync.RWMutex
	secrets map[string]UserSecret
}

// NewInMemorySecretLoader returns an empty loader.
func NewInMemorySecretLoader() *InMemorySecretLoader {
	return &InMemorySecretLoader{secrets: make(map[string]UserSecret)}
}

// Put seeds or replaces the secret for userID.
func (l *InMemorySecretLoader) Put(userID string, us UserSecret) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Clone Secret so a caller that reuses the []byte slice after Put cannot
	// corrupt the stored secret via the shared backing array.
	us.Secret = append([]byte(nil), us.Secret...)
	l.secrets[userID] = us
}

// LoadUserSecret implements UserSecretLoader.
func (l *InMemorySecretLoader) LoadUserSecret(_ context.Context, userID string) (UserSecret, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	us, ok := l.secrets[userID]
	if !ok {
		return UserSecret{}, ErrUserSecretNotFound
	}
	// Clone Secret so the caller cannot corrupt the stored value via the returned slice.
	us.Secret = append([]byte(nil), us.Secret...)
	return us, nil
}

// stubSessionResolver auto-approves a fixed subject. SCAFFOLD only.
type stubSessionResolver struct{ subject string }

// NewStubSessionResolver returns a SessionResolver that always authenticates and
// consents as subject. SCAFFOLD — replace with real passkey login + consent.
func NewStubSessionResolver(subject string) SessionResolver {
	return stubSessionResolver{subject: subject}
}

// Resolve always returns userID="" (empty). This is intentional for unit-test
// simplicity — Token() gates issueRefreshToken on `result.Code.UserID != ""`
// (docs/DESIGN.md §3.5), so any test using stubSessionResolver will NEVER
// receive a refresh token through a full Authorize→Token flow. Use
// PPIDSessionResolver with a FixedAuthSource for refresh-token integration
// tests (see newRefreshFlowServerWithStore in refresh_rotation_test.go).
func (r stubSessionResolver) Resolve(_ context.Context, _ Client, _ string) (string, string, bool, error) {
	return r.subject, "", true, nil
}

// placeholderIssuer returns OBVIOUSLY-FAKE, UNSIGNED tokens.
//
// SCAFFOLD — NOT SECURE, NEVER FOR PRODUCTION. Real tokens are asymmetric-signed
// JWTs (ES256/EdDSA) whose private key never leaves the regional HSM, published
// via JWKS (docs/DESIGN.md §3.3, §7.3). This stub exists only so the /token
// exchange (single-use codes, PKCE, error channels) can be built and tested
// end-to-end before the signing stack lands. The token strings are deliberately
// self-identifying so they can never be mistaken for real credentials.
type placeholderIssuer struct{}

// NewPlaceholderIssuer returns the SCAFFOLD issuer. Replace with the HSM-backed
// JWT signer (docs/DESIGN.md §7.3) before any real deployment.
func NewPlaceholderIssuer() TokenIssuer { return placeholderIssuer{} }

// Issue implements TokenIssuer with unsigned placeholder tokens.
func (placeholderIssuer) Issue(_ context.Context, p IssueParams) (IssuedTokens, error) {
	return IssuedTokens{
		AccessToken: "UNSIGNED_PLACEHOLDER_ACCESS_TOKEN." + p.Subject,
		IDToken:     "UNSIGNED_PLACEHOLDER_ID_TOKEN." + p.Subject,
		TokenType:   "Bearer",
		ExpiresIn:   accessTokenTTLSeconds,
		Scope:       p.Scope,
	}, nil
}
