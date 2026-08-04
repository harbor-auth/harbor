package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/harbor-auth/harbor/internal/bff"
	"github.com/harbor-auth/harbor/internal/webauthn"
)

type bffMFASessionStamper struct{ store bff.BFFSessionStore }

func (s bffMFASessionStamper) StampMFAStepUp(ctx context.Context, userID string, verifiedAt time.Time) error {
	requestID := bff.SessionIDFromContext(ctx)
	if requestID == "" {
		return errors.New("missing authenticated BFF session")
	}
	record, err := s.store.Get(ctx, requestID)
	if err != nil || record.UserID != userID {
		return errors.New("authenticated BFF session does not match MFA user")
	}
	return bff.RecordTOTPStepUp(ctx, s.store, requestID, verifiedAt)
}

func requireSensitiveManagementStepUp(gate *bff.StepUpGate, next http.Handler) http.Handler {
	protected := []string{"/consent-grants", "/audit-events", "/relay-addresses", "/byo-domains", "/recovery/factors", "/mfa/factors", "/compliance/"}
	guarded := gate.Require(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, prefix := range protected {
			if strings.HasPrefix(r.URL.Path, prefix) {
				guarded.ServeHTTP(w, r)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

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
func (a *bffWebAuthnAdapter) FinishLogin(_ context.Context, _ string, _ *protocol.ParsedCredentialAssertionData) (string, bool, error) {
	return "", false, errors.New("bff: non-discoverable login is not supported")
}

// BeginDiscoverableLogin starts a discoverable (passkey/usernameless) assertion
// ceremony.  No user identity is required up front.
func (a *bffWebAuthnAdapter) BeginDiscoverableLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	return a.svc.BeginDiscoverableLogin(ctx)
}

// FinishDiscoverableLogin completes the discoverable assertion.  It
// re-serialises the already-parsed assertion back to JSON because
// webauthn.Service re-parses the raw body internally, then returns the
// base64url-encoded WebAuthn user handle as the BFF session user_id, plus the
// user's real recovery_required status so LoginHandler can scope the session
// correctly (bff.LoginHandler.FinishLoginWithParsedData).
func (a *bffWebAuthnAdapter) FinishDiscoverableLogin(ctx context.Context, sessionKey string, response *protocol.ParsedCredentialAssertionData) (string, bool, error) {
	body, err := json.Marshal(response.Raw)
	if err != nil {
		return "", false, err
	}
	userID, recoveryRequired, _, err := a.svc.FinishDiscoverableLogin(ctx, sessionKey, bytes.NewReader(body))
	if err != nil {
		return "", false, err
	}
	return userID, recoveryRequired, nil
}
