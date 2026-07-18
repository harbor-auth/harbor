package bff

import (
	"net/http"
)

// Middleware returns an HTTP middleware that authenticates requests using the
// BFF session. It reads the __Host-harbor-bff cookie, looks up the session by
// request_id, and if the session has an authenticated user_id, injects it into
// the request context for downstream handlers (via ContextWithUserID).
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

			// Inject the authenticated user ID into the request context.
			ctx := ContextWithUserID(r.Context(), session.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
