package oidc

import (
	"context"
	"sync"
	"time"
)

// Client is an RP registration — the subset of relying_parties (docs/DESIGN.md
// §10) the flow needs. It is passed BY VALUE into the pure validators so they
// stay free of I/O.
type Client struct {
	ID            string
	SectorID      string // groups redirect URIs for PPID derivation (DESIGN §3.2)
	RedirectURIs  []string
	ScopesAllowed []string
}

// HasRedirectURI reports whether uri EXACTLY matches a registered redirect URI
// (docs/DESIGN.md §11.7, §7.4 — exact string match, never prefix/substring:
// loose matching is a classic open-redirect hole).
func (c Client) HasRedirectURI(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// ClientRegistry looks up RP registrations by client_id. Backed by sqlc over
// relying_parties later; in-memory here.
type ClientRegistry interface {
	Lookup(ctx context.Context, clientID string) (Client, bool)
}

// AuthCode is the state captured at /authorize and consumed at /token. It binds
// the PKCE challenge, the resolved subject (PPID), and the exact client/redirect
// so the token exchange can re-verify them.
type AuthCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	Scope               string
	Subject             string // PPID the RP will see (docs/DESIGN.md §3.2)
	UserID              string // internal user UUID; needed to bind a refresh session (§3.5)
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	AuthTime            time.Time // when the user authenticated (OIDC Core §2)
}

// ConsumeStatus is the outcome of AuthCodeStore.Consume.
type ConsumeStatus int

const (
	// ConsumeNotFound: the code was never issued (or was pruned).
	ConsumeNotFound ConsumeStatus = iota
	// ConsumeFirstUse: the code is valid and now marked consumed.
	ConsumeFirstUse
	// ConsumeReused: the code was ALREADY consumed — a theft signal. The caller
	// must reject with invalid_grant AND revoke tokens minted from it
	// (docs/DESIGN.md §11.7, §3.5).
	ConsumeReused
)

// ConsumeResult pairs the status with the stored code (populated for both
// FirstUse and Reused so the caller can act on the theft signal).
type ConsumeResult struct {
	Status ConsumeStatus
	Code   AuthCode
}

// AuthCodeStore issues and consumes single-use authorization codes. Consume is
// TOMBSTONING — it marks a code consumed rather than deleting it — so a second
// presentation is reported as ConsumeReused (not ConsumeNotFound), which is what
// lets Harbor detect code theft. Expiry is enforced by the caller against
// AuthCode.ExpiresAt, keeping this store deliberately dumb.
//
// Peek reads the stored code WITHOUT mutating it, so the caller can validate
// binding + PKCE against a stolen code before burning the legitimate one
// (docs/DESIGN.md §11.7 — a failed exchange must never consume a valid code).
type AuthCodeStore interface {
	Save(ctx context.Context, code AuthCode) error
	// Peek returns the stored code (found=true) and whether it has already been
	// consumed, without changing its state.
	Peek(ctx context.Context, code string) (stored AuthCode, found bool, consumed bool, err error)
	Consume(ctx context.Context, code string) (ConsumeResult, error)
}

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
