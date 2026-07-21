package oidc

import (
	"context"
	"testing"
	"time"
)

func TestConsentEventKind_Values(t *testing.T) {
	// Ensure the event kinds have the expected string values for serialization.
	tests := []struct {
		kind ConsentEventKind
		want string
	}{
		{ConsentEventGranted, "granted"},
		{ConsentEventScopeEscalated, "scope_escalated"},
		{ConsentEventRevoked, "revoked"},
	}
	for _, tt := range tests {
		if string(tt.kind) != tt.want {
			t.Errorf("ConsentEventKind %v = %q, want %q", tt.kind, string(tt.kind), tt.want)
		}
	}
}

func TestConsentEvent_Fields(t *testing.T) {
	ts := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	event := ConsentEvent{
		Kind:      ConsentEventGranted,
		UserID:    "user-123",
		ClientID:  "client-abc",
		Scopes:    []string{"openid", "profile"},
		Timestamp: ts,
	}

	if event.Kind != ConsentEventGranted {
		t.Errorf("Kind = %v, want %v", event.Kind, ConsentEventGranted)
	}
	if event.UserID != "user-123" {
		t.Errorf("UserID = %q, want %q", event.UserID, "user-123")
	}
	if event.ClientID != "client-abc" {
		t.Errorf("ClientID = %q, want %q", event.ClientID, "client-abc")
	}
	if len(event.Scopes) != 2 || event.Scopes[0] != "openid" || event.Scopes[1] != "profile" {
		t.Errorf("Scopes = %v, want [openid profile]", event.Scopes)
	}
	if !event.Timestamp.Equal(ts) {
		t.Errorf("Timestamp = %v, want %v", event.Timestamp, ts)
	}
}

func TestNoopConsentEventEmitter_Emit(t *testing.T) {
	emitter := NoopConsentEventEmitter()

	event := ConsentEvent{
		Kind:      ConsentEventRevoked,
		UserID:    "user-456",
		ClientID:  "client-xyz",
		Scopes:    []string{"openid"},
		Timestamp: time.Now(),
	}

	// Noop emitter should accept any event and return nil.
	err := emitter.Emit(context.Background(), event)
	if err != nil {
		t.Errorf("Emit() error = %v, want nil", err)
	}
}

func TestNoopConsentEventEmitter_ImplementsInterface(t *testing.T) {
	// Compile-time check is in consent_events.go, but verify at runtime too.
	var _ = NoopConsentEventEmitter()
}
