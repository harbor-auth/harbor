package mgmtapi

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEnrollmentSession_SaveAndGet(t *testing.T) {
	s := NewInMemoryEnrollmentSessionStore()
	key, err := NewEnrollmentSessionKey()
	if err != nil {
		t.Fatalf("NewEnrollmentSessionKey: %v", err)
	}
	want := []byte("user-handle-bytes")
	if err := s.Save(context.Background(), key, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.UserHandle(context.Background(), key)
	if err != nil {
		t.Fatalf("UserHandle: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("handle = %q, want %q", got, want)
	}
}

func TestEnrollmentSession_NotFound(t *testing.T) {
	s := NewInMemoryEnrollmentSessionStore()
	if _, err := s.UserHandle(context.Background(), "nope"); !errors.Is(err, ErrEnrollmentSessionNotFound) {
		t.Fatalf("err = %v, want ErrEnrollmentSessionNotFound", err)
	}
}

func TestEnrollmentSession_Expiry(t *testing.T) {
	s := NewInMemoryEnrollmentSessionStore()
	now := time.Now()
	s.now = func() time.Time { return now }
	const key = "k"
	if err := s.Save(context.Background(), key, []byte("h")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Advance past TTL: the entry must now read as absent.
	s.now = func() time.Time { return now.Add(enrollmentSessionTTL + time.Second) }
	if _, err := s.UserHandle(context.Background(), key); !errors.Is(err, ErrEnrollmentSessionNotFound) {
		t.Fatalf("err = %v, want ErrEnrollmentSessionNotFound after expiry", err)
	}
}

func TestEnrollmentSession_SaveCopiesSlice(t *testing.T) {
	s := NewInMemoryEnrollmentSessionStore()
	handle := []byte{1, 2, 3}
	if err := s.Save(context.Background(), "k", handle); err != nil {
		t.Fatalf("Save: %v", err)
	}
	handle[0] = 9 // mutate caller's slice after Save
	got, err := s.UserHandle(context.Background(), "k")
	if err != nil {
		t.Fatalf("UserHandle: %v", err)
	}
	if got[0] != 1 {
		t.Fatalf("stored handle was aliased to caller slice: got[0]=%d, want 1", got[0])
	}
}

func TestEnrollmentSessionKey_Unique(t *testing.T) {
	a, err := NewEnrollmentSessionKey()
	if err != nil {
		t.Fatalf("key a: %v", err)
	}
	b, err := NewEnrollmentSessionKey()
	if err != nil {
		t.Fatalf("key b: %v", err)
	}
	if a == "" || a == b {
		t.Fatalf("keys must be non-empty and unique: %q %q", a, b)
	}
}
