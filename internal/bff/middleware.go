package bff

import (
	"context"
	"errors"
	"net/http"
)

// Sentinel errors for session scope enforcement.
var (
	// ErrRecoveryRequired is returned when a user with recovery_required=true
	// attempts to access a protected resource that requires full session scope.
	ErrRecoveryRequired = errors.New("bff: recovery required before accessing this resource")
)

// sessionScopeKey is the context key for the session scope.
type sessionScopeKey struct{}

// recoveryRequiredKey is the context key for the recovery_required flag.
type recoveryRequiredKey struct{}

// ContextWithSessionScope returns a new context carrying the session scope.
func ContextWithSessionScope(ctx context.Context, scope SessionScope) context.Context {
	return context.WithValue(ctx, sessionScopeKey{}, scope)
}

// SessionScopeFromContext extracts the session scope from the context.
// Returns SessionScopeFull if no scope is set (default to full access).
func SessionScopeFromContext(ctx context.Context) SessionScope {
	v := ctx.Value(sessionScopeKey{})
	if v == nil {
		return SessionScopeFull
	}
	return v.(SessionScope)
}

// ContextWithRecoveryRequired returns a new context carrying the recovery_required flag.
func ContextWithRecoveryRequired(ctx context.Context, required bool) context.Context {
	return context.WithValue(ctx, recoveryRequiredKey{}, required)
}

// RecoveryRequiredFromContext extracts the recovery_required flag from the context.
// Returns false if not set.
func RecoveryRequiredFromContext(ctx context.Context) bool {
	v := ctx.Value(recoveryRequiredKey{})
	if v == nil {
		return false
	}
	return v.(bool)
}

// Middleware returns an HTTP middleware that authenticates requests using the
// BFF session. It reads the __Host-harbor-bff cookie, looks up the session by
// request_id, and if the session has an authenticated user_id, injects it into
// the request context for downstream handlers (via ContextWithUserID).
//
// It also injects the session scope and recovery_required flag into the context
// for downstream guards to enforce enrollment-only restrictions.
//
// If the cookie is absent, invalid, or the session has no user_id yet (passkey
// ceremony not completed), the request proceeds without a user identity in the
// context — downstream handlers (e.g., BFFAuthSource) will return
// ErrNotAuthenticated when they try to read the user_id.
//
// This middleware does NOT reject unauthenticated requests; it only populates
// the context. Authorization decisions are left to the handlers.
func Middleware(store BFFSessionStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := ReadBFFCookie(r)
			if requestID == "" {
				// No BFF session cookie — proceed without user context.
				next.ServeHTTP(w, r)
				return
			}

			session, err := store.Get(r.Context(), requestID)
			if err != nil {
				// Session not found or expired — proceed without user context.
				// Don't clear the cookie here; the handler that consumes the
				// session (e.g., /authorize/complete) will clear it.
				next.ServeHTTP(w, r)
				return
			}

			if session.UserID == "" {
				// Session exists but user hasn't authenticated yet (passkey
				// ceremony not completed) — proceed without user context.
				next.ServeHTTP(w, r)
				return
			}

			// Inject the authenticated user ID, session scope, and recovery status.
			ctx := ContextWithUserID(r.Context(), session.UserID)
			ctx = ContextWithSessionScope(ctx, session.SessionScope)
			ctx = ContextWithRecoveryRequired(ctx, session.RecoveryRequired)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireFullScope returns an HTTP middleware that rejects requests from users
// with enrollment-only session scope (i.e., users with recovery_required=true).
// This is used to protect endpoints like consent dashboard, compliance export,
// and email change until the user completes recovery setup.
//
// Returns 403 Forbidden with a generic error message if the session scope is
// not full. The response does not leak whether the user exists or their
// recovery status.
func RequireFullScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := SessionScopeFromContext(r.Context())
		if scope != SessionScopeFull {
			// User has enrollment-only scope — deny access.
			http.Error(w, "access denied: complete account setup first", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireEnrollmentAllowed returns an HTTP middleware that allows requests only
// for enrollment operations. This is the inverse of RequireFullScope — it's used
// for endpoints that should ONLY be accessible during enrollment (e.g., the
// passkey enrollment endpoint during recovery).
//
// This middleware allows both full-scope and enrollment-only sessions to access
// the protected endpoint — it exists to document intent and for future use if
// we need to restrict full-scope sessions from certain enrollment paths.
func RequireEnrollmentAllowed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Both full and enrollment-only scopes can access enrollment endpoints.
		next.ServeHTTP(w, r)
	})
}
