package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/harbor-auth/harbor/internal/bff"
	"github.com/harbor-auth/harbor/internal/mgmtapi"
)

// bffCallerAdapter adapts bff.UserIDFromContext to satisfy mgmtapi.CallerSource.
// It is the only correct place to wire this bridge: cmd/harbor-mgmt can import
// both internal/bff and internal/mgmtapi without creating a cycle (bff/dashboard.go
// already imports mgmtapi, so mgmtapi importing bff would be circular).
type bffCallerAdapter struct{}

// Compile-time proof the adapter satisfies mgmtapi.CallerSource.
var _ mgmtapi.CallerSource = bffCallerAdapter{}

// CallerID returns the authenticated user's internal ID from the BFF session
// context, or "" when no authenticated session is present.
func (bffCallerAdapter) CallerID(ctx context.Context) string {
	if bff.SessionScopeFromContext(ctx) == bff.SessionScopeEnrollmentOnly {
		return ""
	}
	return bff.UserIDFromContext(ctx)
}

func (bffCallerAdapter) SessionID(ctx context.Context) string {
	return bff.SessionIDFromContext(ctx)
}

// recoverySessionIssuer establishes the two server-side records needed after a
// recovery code is consumed: a scoped BFF session for authorization and an
// enrollment handoff for the WebAuthn registration ceremony. Both records use
// the same opaque token and shared stores, so the next request may land on any
// management replica.
type recoverySessionIssuer struct {
	bffSessions        bff.BFFSessionStore
	enrollmentSessions mgmtapi.EnrollmentSessionStore
}

var _ mgmtapi.ScopedSessionIssuer = (*recoverySessionIssuer)(nil)

func (i *recoverySessionIssuer) IssueEnrollmentSession(ctx context.Context, userID string) (string, error) {
	if i == nil || i.bffSessions == nil || i.enrollmentSessions == nil {
		return "", fmt.Errorf("recovery session issuer is not configured")
	}
	token, err := mgmtapi.NewEnrollmentSessionKey()
	if err != nil {
		return "", fmt.Errorf("generate recovery session token: %w", err)
	}
	handle, err := recoveryUserHandle(userID)
	if err != nil {
		return "", err
	}
	if err := i.enrollmentSessions.Save(ctx, token, handle, true); err != nil {
		return "", fmt.Errorf("save recovery enrollment handoff: %w", err)
	}
	if err := i.bffSessions.Create(ctx, bff.BFFSessionRecord{
		RequestID:        token,
		UserID:           userID,
		SessionScope:     bff.SessionScopeEnrollmentOnly,
		RecoveryRequired: true,
		ExpiresAt:        time.Now().Add(10 * time.Minute),
	}); err != nil {
		return "", fmt.Errorf("save scoped recovery session: %w", err)
	}
	return token, nil
}

func recoveryUserHandle(userID string) ([]byte, error) {
	if id, err := uuid.Parse(userID); err == nil {
		return id[:], nil
	}
	handle, err := base64.RawURLEncoding.DecodeString(userID)
	if err != nil || len(handle) == 0 {
		return nil, fmt.Errorf("decode recovery user handle")
	}
	return handle, nil
}

// recoveryCompleteStore is the narrow surface this file needs from
// *webauthn.DBStore to clear recovery_required — the SAME store method
// internal/webauthn/service.go's FinishRecoveryRegistration calls after a
// lost-device recovery ceremony re-enrolls a passkey. Declaring it locally
// (instead of importing internal/webauthn for its Store interface) keeps this
// file duck-typed against exactly the one method it needs.
type recoveryCompleteStore interface {
	SetRecoveryComplete(ctx context.Context, userID []byte) error
}

// recoveryRequirementClearer adapts recoveryCompleteStore to
// mgmtapi.RecoveryRequirementClearer so POST /recovery/acknowledge clears
// recovery_required through the exact same DB write
// FinishRecoveryRegistration uses — never a second, parallel mechanism. The
// mgmtapi-side userID is always the canonical UUID text form (see
// bffCallerAdapter / recoverySessionIssuer), which is exactly what
// webauthn.DBStore's parseWebAuthnUserID expects — unlike the raw 16-byte
// WebAuthn "user handle" form recoveryUserHandle produces for enrollment
// sessions, so no conversion belongs here.
type recoveryRequirementClearer struct {
	store recoveryCompleteStore
}

var _ mgmtapi.RecoveryRequirementClearer = recoveryRequirementClearer{}

func (c recoveryRequirementClearer) ClearRecoveryRequired(ctx context.Context, userID string) error {
	return c.store.SetRecoveryComplete(ctx, []byte(userID))
}

// bffSessionScopeRefresher adapts bff.BFFSessionStore.SetUserWithRecoveryStatus
// to mgmtapi.RecoverySessionRefresher, so POST /recovery/acknowledge can
// refresh the caller's already-issued BFF session scope in place — the same
// primitive the BFF session middleware already relies on to stamp scope.
type bffSessionScopeRefresher struct {
	bffSessions bff.BFFSessionStore
}

var _ mgmtapi.RecoverySessionRefresher = bffSessionScopeRefresher{}

func (r bffSessionScopeRefresher) RefreshSessionScope(ctx context.Context, sessionID, userID string, recoveryRequired bool) error {
	if sessionID == "" {
		return fmt.Errorf("recovery session refresh: missing BFF session id")
	}
	return r.bffSessions.SetUserWithRecoveryStatus(ctx, sessionID, userID, recoveryRequired)
}

// bffEnrollmentCallerAdapter resolves the authenticated caller for endpoints
// explicitly designed to run during BOTH full and enrollment-only session
// scope (bff.RequireEnrollmentAllowed's contract) — today, only
// recoverySessionCaller's fallback for POST /recovery/codes and POST
// /recovery/acknowledge. Unlike bffCallerAdapter it does NOT refuse
// enrollment-only sessions; it must only ever be wired to handlers that are
// safe under that scope.
type bffEnrollmentCallerAdapter struct{}

var _ mgmtapi.CallerSessionSource = bffEnrollmentCallerAdapter{}

func (bffEnrollmentCallerAdapter) CallerID(ctx context.Context) string {
	return bff.UserIDFromContext(ctx)
}

func (bffEnrollmentCallerAdapter) SessionID(ctx context.Context) string {
	return bff.SessionIDFromContext(ctx)
}

// postRegistrationHandoffTTL bounds the enrollment-only session issued right
// after first-passkey registration. It matches the lost-device recovery
// ceremony's own window (PostRecoveryComplete's recoveryCeremonyTTL) since
// both establish the exact same session type for the exact same purpose:
// complete mandatory recovery setup, nothing else.
const postRegistrationHandoffTTL = 10 * time.Minute

// postRegistrationHandoffWriter lets wirePostRegistrationHandoff observe the
// wrapped handler's status code and inject an extra Set-Cookie header BEFORE
// the response is committed to the wire, without buffering the body.
type postRegistrationHandoffWriter struct {
	http.ResponseWriter
	committed bool
	onSuccess func()
}

func (w *postRegistrationHandoffWriter) WriteHeader(status int) {
	if !w.committed {
		w.committed = true
		if status == http.StatusOK && w.onSuccess != nil {
			w.onSuccess()
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *postRegistrationHandoffWriter) Write(b []byte) (int, error) {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// wirePostRegistrationHandoff wraps the WebAuthn register/finish route so a
// user's FIRST successful passkey registration immediately fires
// ScopedSessionIssuer.IssueEnrollmentSession — the exact seam
// PostRecoveryComplete already uses to land a recovering user in
// bff.SessionScopeEnrollmentOnly (recoverySessionIssuer, above) — instead of
// leaving a brand-new signup user with no BFF session at all until they sign
// back in. It never adds a second session type: the resulting session is
// indistinguishable from one the lost-device recovery ceremony would produce.
//
// The user id comes from the SAME enrollment-session cookie the ceremony
// itself reads to resolve who is registering (§9, §11.1) — this handler never
// introduces a client-supplied identity. A handoff failure (issuer error,
// missing/invalid cookie, store miss) never turns a successful ceremony into
// an error response: the credential is already durably persisted by the time
// onSuccess runs, so retrying the ceremony would only confuse the client. The
// user simply needs a fresh sign-in if the handoff itself did not land.
func wirePostRegistrationHandoff(next http.Handler, sessions mgmtapi.EnrollmentSessionStore, issuer mgmtapi.ScopedSessionIssuer, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, cookieErr := r.Cookie(mgmtapi.EnrollmentSessionCookieName)
		wrapped := &postRegistrationHandoffWriter{ResponseWriter: w}
		wrapped.onSuccess = func() {
			if cookieErr != nil || cookie.Value == "" || sessions == nil || issuer == nil {
				return
			}
			handle, _, err := sessions.UserHandle(r.Context(), cookie.Value)
			if err != nil || len(handle) != 16 {
				return
			}
			userID := uuid.UUID(handle).String()
			token, err := issuer.IssueEnrollmentSession(r.Context(), userID)
			if err != nil {
				logger.ErrorContext(r.Context(), "post-registration handoff: issue enrollment session failed", "error", err)
				return
			}
			setPostRegistrationHandoffCookies(w, token)
		}
		next.ServeHTTP(wrapped, r)
	})
}

// setPostRegistrationHandoffCookies sets the exact pair of cookies
// PostRecoveryComplete sets on a successful recovery ceremony: the scoped BFF
// session cookie and the enrollment handoff cookie the WebAuthn ceremony
// endpoints read, both keyed by the same opaque token.
func setPostRegistrationHandoffCookies(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     mgmtapi.RecoveryScopedSessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(postRegistrationHandoffTTL.Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     mgmtapi.EnrollmentSessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(postRegistrationHandoffTTL.Seconds()),
	})
}
