// Package oidcapi implements the spec-generated OpenAPI ServerInterface
// (internal/gen/openapi) for Harbor's hot-path HTTP surface.
//
// The OpenAPI contract in api/openapi/harbor.yaml is the source of truth
// (docs/DESIGN.md §1.2). This package is the hand-written business logic that
// *satisfies* the generated interface — the generated stubs are never edited by
// hand (§1.3); if code and spec disagree, the spec wins and we regenerate.
package oidcapi

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/harbor/harbor/internal/bff"
	"github.com/harbor/harbor/internal/crypto"
	"github.com/harbor/harbor/internal/gen/openapi"
	"github.com/harbor/harbor/internal/oidc"
)

// DefaultBFFSessionTTL is the default lifetime of BFF session records in the
// oidcapi Server (docs/plans/bff-session-middleware.md — 5 min, matching the
// PKCE state lifetime).
const DefaultBFFSessionTTL = 5 * time.Minute

// Server implements openapi.ServerInterface for the harbor-hot binary.
type Server struct {
	issuer    string
	svc       *oidc.Service
	jwksBytes []byte
	// signers are the public signing keys used to verify inbound access tokens
	// on the /userinfo endpoint. The first is the active signer; additional
	// entries support rotation overlap (§7.3).
	signers       []crypto.Signer
	bffSessions   bff.BFFSessionStore
	loginURL      *url.URL // parsed at construction; nil if BFF not configured
	bffSessionTTL time.Duration
	// rotator drives POST /admin/keys/rotate (§7.3, §3.5.4). May be nil, in
	// which case the rotate endpoint reports 501 Not Implemented.
	rotator *crypto.KeyRotator
}

// Config holds the settings needed to serve the OIDC surface.
type Config struct {
	// Issuer is this region's OIDC issuer URL (docs/DESIGN.md §3.4), e.g.
	// https://eu.harbor.id. It anchors every endpoint in the discovery document.
	Issuer string
	// Service runs the /authorize + /token flow logic. May be nil for the
	// discovery-only tests, which never exercise those endpoints.
	Service *oidc.Service
	// Signers are the public signing keys published at /jwks.json. The first is
	// the active signer; additional entries support rotation overlap (§7.3).
	// May be empty for discovery-only tests (served as {"keys":[]}).
	Signers []crypto.Signer
	// BFFSessions is the BFF session store. When non-nil, /authorize creates a
	// BFF session and redirects to LoginURL rather than issuing a code directly.
	BFFSessions bff.BFFSessionStore
	// LoginURL is the URL of the login UI (e.g. "https://mgmt.harbor.id/login").
	// Required when BFFSessions is non-nil.
	LoginURL string
	// BFFSessionTTL overrides DefaultBFFSessionTTL when non-zero.
	BFFSessionTTL time.Duration
	// Rotator drives POST /admin/keys/rotate (§7.3, §3.5.4). May be nil, in
	// which case the rotate endpoint reports 501 Not Implemented.
	Rotator *crypto.KeyRotator
}

// New returns a Server that serves the generated OpenAPI contract. The JWKS
// document is precomputed here because it changes only on key rotation.
func New(cfg Config) *Server {
	jwksBytes, err := json.Marshal(oidc.BuildJWKS(cfg.Signers))
	if err != nil {
		// Pure struct → JSON cannot fail in practice; serve an empty-keys JWKS
		// rather than panic or 500 if it somehow does.
		jwksBytes = []byte(`{"keys":[]}`)
	}
	ttl := cfg.BFFSessionTTL
	if ttl == 0 {
		ttl = DefaultBFFSessionTTL
	}
	var parsedLoginURL *url.URL
	if cfg.LoginURL != "" {
		var parseErr error
		parsedLoginURL, parseErr = url.Parse(cfg.LoginURL)
		if parseErr != nil {
			// Malformed LoginURL → treat as unconfigured; /authorize falls back
			// to the legacy immediate-code flow (docs/DESIGN.md §9).
			parsedLoginURL = nil
		}
	}
	return &Server{
		issuer:        cfg.Issuer,
		svc:           cfg.Service,
		jwksBytes:     jwksBytes,
		signers:       cfg.Signers,
		bffSessions:   cfg.BFFSessions,
		loginURL:      parsedLoginURL,
		bffSessionTTL: ttl,
		rotator:       cfg.Rotator,
	}
}

// Compile-time proof that Server satisfies the generated contract. If the spec
// grows a new operation, this stops compiling until we implement it — so the
// spec can never silently outrun the server.
var _ openapi.ServerInterface = (*Server)(nil)

// writeError renders the generated Error envelope as JSON. Messages must carry
// no PII (docs/DESIGN.md §6.5).
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(openapi.Error{Code: code, Message: message})
}
