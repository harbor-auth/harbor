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

	"github.com/harbor/harbor/internal/crypto"
	"github.com/harbor/harbor/internal/gen/openapi"
	"github.com/harbor/harbor/internal/oidc"
)

// Server implements openapi.ServerInterface for the harbor-hot binary.
type Server struct {
	issuer    string
	svc       *oidc.Service
	jwksBytes []byte
	// signers are the public signing keys used to verify inbound access tokens
	// on the /userinfo endpoint. The first is the active signer; additional
	// entries support rotation overlap (§7.3).
	signers []crypto.Signer
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
	return &Server{issuer: cfg.Issuer, svc: cfg.Service, jwksBytes: jwksBytes, signers: cfg.Signers}
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
