package main

import (
	"context"

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
	return bff.UserIDFromContext(ctx)
}
