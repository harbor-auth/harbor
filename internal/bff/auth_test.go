package bff

import (
	"context"
	"errors"
	"testing"
)

func TestContextWithUserID_AndUserIDFromContext(t *testing.T) {
	ctx := context.Background()
	userID := "user-123"

	ctxWithUser := ContextWithUserID(ctx, userID)

	got := UserIDFromContext(ctxWithUser)
	if got != userID {
		t.Errorf("UserIDFromContext() = %q, want %q", got, userID)
	}
}

func TestUserIDFromContext_NoUserID(t *testing.T) {
	ctx := context.Background()

	got := UserIDFromContext(ctx)
	if got != "" {
		t.Errorf("UserIDFromContext() = %q, want empty string", got)
	}
}

func TestBFFAuthSource_AuthenticatedUserID(t *testing.T) {
	auth := NewBFFAuthSource()
	userID := "user-456"
	ctx := ContextWithUserID(context.Background(), userID)

	got, err := auth.AuthenticatedUserID(ctx)
	if err != nil {
		t.Fatalf("AuthenticatedUserID() error = %v", err)
	}
	if got != userID {
		t.Errorf("AuthenticatedUserID() = %q, want %q", got, userID)
	}
}

func TestBFFAuthSource_AuthenticatedUserID_NotAuthenticated(t *testing.T) {
	auth := NewBFFAuthSource()
	ctx := context.Background()

	_, err := auth.AuthenticatedUserID(ctx)
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("AuthenticatedUserID() error = %v, want ErrNotAuthenticated", err)
	}
}

func TestBFFAuthSource_AuthenticatedUserID_EmptyUserID(t *testing.T) {
	auth := NewBFFAuthSource()
	// Even if context has a user ID key with empty string, treat as not authenticated
	ctx := ContextWithUserID(context.Background(), "")

	_, err := auth.AuthenticatedUserID(ctx)
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("AuthenticatedUserID() error = %v, want ErrNotAuthenticated", err)
	}
}
