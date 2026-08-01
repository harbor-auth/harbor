package main

import (
	"context"
	"encoding/base64"
	"fmt"
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
	if err := i.enrollmentSessions.Save(ctx, token, handle); err != nil {
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
