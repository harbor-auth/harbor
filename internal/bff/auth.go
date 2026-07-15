package bff

import (
	"context"
	"errors"
)

// ErrNotAuthenticated is returned when the request context does not contain an
// authenticated user identity. This happens when the BFF session middleware has
// not yet set the user_id (i.e., the passkey ceremony has not completed).
var ErrNotAuthenticated = errors.New("bff: not authenticated")

// userIDKey is the context key for the authenticated user's internal ID.
type userIDKey struct{}

// ContextWithUserID returns a new context carrying the authenticated user ID.
// This is called by the BFF middleware after FinishAssertion to propagate the
// identity to downstream handlers.
func ContextWithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey{}, userID)
}

// UserIDFromContext extracts the authenticated user ID from the context.
// Returns empty string if no user ID is set.
func UserIDFromContext(ctx context.Context) string {
	v := ctx.Value(userIDKey{})
	if v == nil {
		return ""
	}
	return v.(string)
}

// BFFAuthSource reads the authenticated user's identity from the request
// context, where it was placed by the BFF session middleware after a successful
// passkey ceremony. This replaces FixedAuthSource in production.
//
// The context-based approach (vs. reading from BFFSessionStore directly) keeps
// the oidc package free of internal/bff imports and allows the auth check to be
// a simple context lookup — the middleware has already validated the session.
type BFFAuthSource struct{}

// NewBFFAuthSource returns an AuthSource backed by the BFF session middleware.
func NewBFFAuthSource() *BFFAuthSource {
	return &BFFAuthSource{}
}

// AuthenticatedUserID implements oidc.AuthSource. It reads the user ID from the
// request context (set by BFF middleware) and returns ErrNotAuthenticated if
// the context has no authenticated identity.
func (a *BFFAuthSource) AuthenticatedUserID(ctx context.Context) (string, error) {
	userID := UserIDFromContext(ctx)
	if userID == "" {
		return "", ErrNotAuthenticated
	}
	return userID, nil
}
