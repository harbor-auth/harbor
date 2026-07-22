package webauthn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// ErrClonedAuthenticator is returned from FinishLogin when the authenticator's
// signature counter regressed — a signal the passkey may have been cloned
// (docs/DESIGN.md §3.1). Harbor fails the assertion closed rather than scoring
// the risk, consistent with the security-first posture.
var ErrClonedAuthenticator = errors.New("webauthn: possible cloned authenticator (sign count regression)")

// Config is the Relying Party configuration for the ceremonies.
type Config struct {
	// RPID is the Relying Party ID — the effective domain, no scheme/port
	// (e.g. "harbor.id"). Passkeys are scoped to it.
	RPID string
	// RPDisplayName is a human-facing name shown by the authenticator UI.
	RPDisplayName string
	// RPOrigins are the fully-qualified origins permitted to run ceremonies
	// (e.g. "https://eu.harbor.id").
	RPOrigins []string
}

// Service runs the passkey registration and assertion ceremonies. It owns the
// certified go-webauthn engine and coordinates the Store (credentials) and
// SessionStore (challenges); it holds no per-request state.
type Service struct {
	wa       *gowebauthn.WebAuthn
	store    Store
	sessions SessionStore
}

// NewService validates the RP config and returns a ready Service.
func NewService(cfg Config, store Store, sessions SessionStore) (*Service, error) {
	wa, err := gowebauthn.New(&gowebauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, err
	}
	return &Service{wa: wa, store: store, sessions: sessions}, nil
}

// BeginRegistration starts enrolling a new passkey for an existing user. It
// returns the creation options to relay to the browser and an opaque session
// key the caller must echo back to FinishRegistration (via an HttpOnly cookie).
func (s *Service) BeginRegistration(ctx context.Context, userID []byte) (*protocol.CredentialCreation, string, error) {
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	options, session, err := s.wa.BeginRegistration(user)
	if err != nil {
		return nil, "", err
	}
	return s.persistSession(ctx, options, session)
}

// FinishRegistration verifies the authenticator's attestation response against
// the stored challenge and, on success, persists the new passkey.
func (s *Service) FinishRegistration(ctx context.Context, userID []byte, sessionKey string, body io.Reader) (*gowebauthn.Credential, error) {
	cred, err := s.verifyRegistration(ctx, userID, sessionKey, body)
	if err != nil {
		return nil, err
	}
	// First-passkey registration completes enrollment: persist the credential
	// and flip the user from "pending" to "active" atomically (design decision 3,
	// §11.1). A DB-backed store does both in one transaction and rolls back on
	// any failure, so we never leave a half-enrolled account.
	if err := s.store.AddCredentialAndActivateUser(ctx, userID, *cred); err != nil {
		return nil, err
	}
	return cred, nil
}

// FinishRecoveryRegistration verifies the attestation for a passkey enrolled
// during an account-recovery session and, on success, persists the fresh
// credential and THEN clears the user's recovery_required flag (REQ-005,
// docs/DESIGN.md §11.1).
//
// Ordering is the whole point: the credential is stored first, and
// recovery_required is cleared only after that write succeeds. If either write
// fails the flag stays set, so the account remains fenced to enrollment-only
// and can never be "recovered" without a working fresh passkey. Unlike
// first-time enrollment this uses AddCredential (not
// AddCredentialAndActivateUser): a recovering user is already active.
func (s *Service) FinishRecoveryRegistration(ctx context.Context, userID []byte, sessionKey string, body io.Reader) (*gowebauthn.Credential, error) {
	cred, err := s.verifyRegistration(ctx, userID, sessionKey, body)
	if err != nil {
		return nil, err
	}
	if err := s.store.AddCredential(ctx, userID, *cred); err != nil {
		return nil, err
	}
	// Only now — after a fresh passkey is durably enrolled — clear the recovery
	// requirement so normal-scope sessions become available again.
	if err := s.store.SetRecoveryComplete(ctx, userID); err != nil {
		return nil, err
	}
	return cred, nil
}

// verifyRegistration takes the stored ceremony session and validates the
// authenticator's attestation, returning the new credential. It is shared by
// the first-time and recovery registration paths so their verification cannot
// diverge; only the persistence step after it differs.
func (s *Service) verifyRegistration(ctx context.Context, userID []byte, sessionKey string, body io.Reader) (*gowebauthn.Credential, error) {
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	session, err := s.sessions.Take(ctx, sessionKey)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(body)
	if err != nil {
		return nil, err
	}
	return s.wa.CreateCredential(user, session, parsed)
}

// BeginLogin starts an assertion for a known user. It returns the assertion
// options and an opaque session key (echoed to FinishLogin via cookie).
func (s *Service) BeginLogin(ctx context.Context, userID []byte) (*protocol.CredentialAssertion, string, error) {
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	options, session, err := s.wa.BeginLogin(user)
	if err != nil {
		return nil, "", err
	}
	key, err := newSessionKey()
	if err != nil {
		return nil, "", err
	}
	if err := s.sessions.Save(ctx, key, *session); err != nil {
		return nil, "", err
	}
	return options, key, nil
}

// FinishLogin verifies the authenticator's assertion response. On success it
// persists the advanced signature counter; if the counter regressed it fails
// closed with ErrClonedAuthenticator and does NOT update the stored counter.
func (s *Service) FinishLogin(ctx context.Context, userID []byte, sessionKey string, body io.Reader) (*gowebauthn.Credential, error) {
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	session, err := s.sessions.Take(ctx, sessionKey)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(body)
	if err != nil {
		return nil, err
	}
	cred, err := s.wa.ValidateLogin(user, session, parsed)
	if err != nil {
		return nil, err
	}
	if cred.Authenticator.CloneWarning {
		return nil, ErrClonedAuthenticator
	}
	if err := s.store.UpdateCredential(ctx, userID, *cred); err != nil {
		return nil, err
	}
	return cred, nil
}

// persistSession stores the registration session under a fresh key and returns
// the options + key. Shared by the registration begin path.
func (s *Service) persistSession(ctx context.Context, options *protocol.CredentialCreation, session *gowebauthn.SessionData) (*protocol.CredentialCreation, string, error) {
	key, err := newSessionKey()
	if err != nil {
		return nil, "", err
	}
	if err := s.sessions.Save(ctx, key, *session); err != nil {
		return nil, "", err
	}
	return options, key, nil
}

// newSessionKey returns a 256-bit random, URL-safe opaque session identifier.
func newSessionKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
