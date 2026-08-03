// SPDX-License-Identifier: Apache-2.0

// Command minimal-rp is a minimal, executable relying-party (RP) reference
// implementation for "Sign in with Private Harbor". It exists to demonstrate
// — in runnable code, not just documentation — the security model the
// button/component kit assumes: the RP, not the button, owns state, nonce,
// PKCE, redirect-URI allowlisting, session rotation, and callback error
// handling. See ../../docs/SECURITY.md for the full explanation.
//
// Run:
//
//	ISSUER=https://auth.example.com \
//	CLIENT_ID=your-client-id \
//	REDIRECT_URI=http://localhost:8080/auth/callback \
//	go run ./sdk/sign-in-button/examples/minimal-rp
//
// See README.md for the full list of environment variables.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultAddr = ":8080"

	// sessionCookieName is used for both the pre-auth (pending) session,
	// minted by LoginHandler, and the post-auth session, minted by
	// CallbackHandler after rotation. It is HttpOnly, so it is never
	// readable by JavaScript on either side of the flow.
	sessionCookieName = "phb_rp_session"

	// pendingAuthTTL bounds how long a minted state/nonce/code_verifier
	// stays redeemable. It must comfortably exceed the time a real user
	// takes to authenticate at the identity provider, but expire quickly
	// enough to bound the window an abandoned/stolen pending session is
	// exploitable.
	pendingAuthTTL = 10 * time.Minute
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	issuer := os.Getenv("ISSUER")
	clientID := os.Getenv("CLIENT_ID")
	redirectURI := os.Getenv("REDIRECT_URI")
	if issuer == "" || clientID == "" || redirectURI == "" {
		return fmt.Errorf("ISSUER, CLIENT_ID, and REDIRECT_URI environment variables are all required")
	}

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = defaultAddr
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}

	discoverCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	doc, err := discoverOIDC(discoverCtx, httpClient, issuer)
	if err != nil {
		return fmt.Errorf("OIDC discovery against %s failed: %w", issuer, err)
	}

	sessions := newSessionStore()

	mux := http.NewServeMux()
	mux.Handle("/auth/login", &LoginHandler{
		AuthorizeURL: doc.AuthorizationEndpoint,
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		Sessions:     sessions,
	})
	mux.Handle("/auth/callback", &CallbackHandler{
		TokenEndpoint: doc.TokenEndpoint,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		Issuer:        issuer,
		Sessions:      sessions,
		HTTPClient:    httpClient,
	})

	log.Printf("minimal-rp listening on %s (issuer=%s, client_id=%s)", addr, issuer, clientID)
	return http.ListenAndServe(addr, mux)
}

// discoveryDocument is the subset of the OIDC discovery document
// (".well-known/openid-configuration", OpenID Connect Discovery 1.0 §3)
// this example needs.
type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// discoverOIDC fetches and validates the issuer's discovery document. The
// returned issuer is required to match the configured one exactly (no
// trailing-slash or scheme normalization) per the discovery spec, so a
// misconfigured or spoofed discovery document can't silently redirect the
// flow to a different issuer.
func discoverOIDC(ctx context.Context, client *http.Client, issuer string) (discoveryDocument, error) {
	discoveryURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return discoveryDocument{}, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return discoveryDocument{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return discoveryDocument{}, fmt.Errorf("GET %s: unexpected status %d", discoveryURL, resp.StatusCode)
	}

	var doc discoveryDocument
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return discoveryDocument{}, fmt.Errorf("decoding discovery document: %w", err)
	}
	if doc.Issuer != issuer {
		return discoveryDocument{}, fmt.Errorf("discovery document issuer %q does not match configured ISSUER %q", doc.Issuer, issuer)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return discoveryDocument{}, fmt.Errorf("discovery document missing authorization_endpoint or token_endpoint")
	}
	return doc, nil
}

// PendingAuth is the server-side record of an in-flight authorization
// request: the values LoginHandler minted and CallbackHandler must later
// verify against the identity provider's response.
type PendingAuth struct {
	State        string
	Nonce        string
	CodeVerifier string
	CreatedAt    time.Time
}

// Session is an established, post-login RP session.
type Session struct {
	Subject  string
	IssuedAt time.Time
}

// sessionStore holds both pending (pre-login) and established (post-login)
// sessions, keyed by the opaque, random identifier carried in
// sessionCookieName. It is process-local and in-memory, which is
// appropriate for this example; a production RP would typically back it
// with a shared store (e.g. Redis) so any instance can serve the callback.
type sessionStore struct {
	mu       sync.Mutex
	pending  map[string]PendingAuth
	sessions map[string]Session
}

func newSessionStore() *sessionStore {
	return &sessionStore{
		pending:  make(map[string]PendingAuth),
		sessions: make(map[string]Session),
	}
}

func (s *sessionStore) putPending(id string, p PendingAuth) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[id] = p
}

// takePending atomically fetches and deletes id's pending authorization, so
// a given pre-auth session (and the state it carries) can be redeemed at
// most once — a second callback for the same session is rejected exactly
// like an unknown one.
func (s *sessionStore) takePending(id string) (PendingAuth, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[id]
	if !ok {
		return PendingAuth{}, false
	}
	delete(s.pending, id)
	if time.Since(p.CreatedAt) > pendingAuthTTL {
		return PendingAuth{}, false
	}
	return p, true
}

func (s *sessionStore) putSession(id string, sess Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = sess
}
