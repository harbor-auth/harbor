package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/harbor-auth/harbor/internal/bff"
	"github.com/harbor-auth/harbor/internal/webauthn"
)

// bffWebAuthnAdapter bridges bff.WebAuthnService to *webauthn.Service.
//
// The adapter delegates all ceremony work to webauthn.Service and returns the
// base64url-encoded WebAuthn user handle as the BFF session user_id.  The
// application always wires bff.DiscoverableUserResolver so only the
// discoverable (passkey/usernameless) path is exercised at runtime.
type bffWebAuthnAdapter struct {
	svc *webauthn.Service
}

// newBFFWebAuthnAdapter wraps a webauthn.Service for use by bff.LoginHandler.
func newBFFWebAuthnAdapter(svc *webauthn.Service) *bffWebAuthnAdapter {
	return &bffWebAuthnAdapter{svc: svc}
}

// Compile-time proof the adapter satisfies the interface bff.LoginHandler needs.
var _ bff.WebAuthnService = (*bffWebAuthnAdapter)(nil)

// BeginLogin starts a known-user assertion ceremony.
func (a *bffWebAuthnAdapter) BeginLogin(ctx context.Context, userID []byte) (*protocol.CredentialAssertion, string, error) {
	return a.svc.BeginLogin(ctx, userID)
}

// FinishLogin is not used when the application is wired with
// bff.DiscoverableUserResolver.  It fails closed to prevent accidental use.
func (a *bffWebAuthnAdapter) FinishLogin(_ context.Context, _ string, _ *protocol.ParsedCredentialAssertionData) (string, error) {
	return "", errors.New("bff: non-discoverable login is not supported")
}

// BeginDiscoverableLogin starts a discoverable (passkey/usernameless) assertion
// ceremony.  No user identity is required up front.
func (a *bffWebAuthnAdapter) BeginDiscoverableLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	return a.svc.BeginDiscoverableLogin(ctx)
}

// FinishDiscoverableLogin completes the discoverable assertion.  It
// re-serialises the already-parsed assertion back to JSON because
// webauthn.Service re-parses the raw body internally, then returns the
// base64url-encoded WebAuthn user handle as the BFF session user_id.
func (a *bffWebAuthnAdapter) FinishDiscoverableLogin(ctx context.Context, sessionKey string, response *protocol.ParsedCredentialAssertionData) (string, error) {
	body, err := json.Marshal(response.Raw)
	if err != nil {
		return "", err
	}
	userID, _, err := a.svc.FinishDiscoverableLogin(ctx, sessionKey, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	return userID, nil
}
