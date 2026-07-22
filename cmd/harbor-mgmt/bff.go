package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/harbor-auth/harbor/internal/bff"
	"github.com/harbor-auth/harbor/internal/webauthn"
)

// bffWebAuthnAdapter bridges bff.WebAuthnService to *webauthn.Service.
//
// The BFF login flow (internal/bff) returns the authenticated user_id from
// FinishLogin, but webauthn.Service.FinishLogin requires the user handle up
// front. The adapter remembers the user handle keyed by the ceremony session
// key between BeginLogin and FinishLogin, then returns it (base64url-encoded)
// as the BFF session user_id.
type bffWebAuthnAdapter struct {
	svc *webauthn.Service

	mu    sync.Mutex
	byKey map[string][]byte // ceremony session key -> WebAuthn user handle
}

// newBFFWebAuthnAdapter wraps a webauthn.Service for use by bff.LoginHandler.
func newBFFWebAuthnAdapter(svc *webauthn.Service) *bffWebAuthnAdapter {
	return &bffWebAuthnAdapter{svc: svc, byKey: make(map[string][]byte)}
}

// Compile-time proof the adapter satisfies the interface bff.LoginHandler needs.
var _ bff.WebAuthnService = (*bffWebAuthnAdapter)(nil)

// BeginLogin starts the assertion and records the user handle against the
// returned ceremony session key so FinishLogin can recover it.
func (a *bffWebAuthnAdapter) BeginLogin(ctx context.Context, userID []byte) (*protocol.CredentialAssertion, string, error) {
	options, key, err := a.svc.BeginLogin(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	a.mu.Lock()
	a.byKey[key] = userID
	a.mu.Unlock()
	return options, key, nil
}

// FinishLogin completes the assertion and returns the authenticated user's
// internal ID (the base64url-encoded WebAuthn user handle) for the BFF session.
func (a *bffWebAuthnAdapter) FinishLogin(ctx context.Context, sessionKey string, response *protocol.ParsedCredentialAssertionData) (string, error) {
	a.mu.Lock()
	userID := a.byKey[sessionKey]
	delete(a.byKey, sessionKey)
	a.mu.Unlock()

	// webauthn.Service.FinishLogin re-parses the raw body, so re-serialize the
	// already-parsed assertion response back to JSON.
	body, err := json.Marshal(response.Raw)
	if err != nil {
		return "", err
	}
	if _, err := a.svc.FinishLogin(ctx, userID, sessionKey, bytes.NewReader(body)); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(userID), nil
}

// devUserResolver resolves the WebAuthn user handle from a base64url `user_id`
// query parameter. This is a DEV scaffold that identifies WHICH user to
// challenge — the passkey assertion still must be proven, so it is not the
// impersonation hole the old handlers.go path was. Real deployments will
// replace this with a resolver that looks the user up from their submitted
// email/username (docs/plans/bff-session-middleware.md).
type devUserResolver struct{}

// Compile-time proof the resolver satisfies the interface.
var _ bff.UserResolver = (*devUserResolver)(nil)

// ResolveUser returns the user handle decoded from the request's `user_id`
// query parameter, or ErrUserNotIdentified when it is absent or malformed.
func (devUserResolver) ResolveUser(_ context.Context, r *http.Request, _ bff.BFFSessionRecord) ([]byte, error) {
	raw := r.URL.Query().Get("user_id")
	if raw == "" {
		return nil, bff.ErrUserNotIdentified
	}
	userID, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(userID) == 0 {
		return nil, bff.ErrUserNotIdentified
	}
	return userID, nil
}
