package relay

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/uuid"

	"github.com/harbor/harbor/internal/region"
)

func TestTokenGenerator_Generate(t *testing.T) {
	gen := NewTokenGenerator()

	t.Run("produces non-empty token", func(t *testing.T) {
		token, err := gen.Generate()
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
		if token == "" {
			t.Error("Generate() returned empty token")
		}
		// 20 bytes base64url encoded = 27 characters (no padding)
		if len(token) != 27 {
			t.Errorf("Generate() token length = %d, want 27", len(token))
		}
	})

	t.Run("produces unique tokens", func(t *testing.T) {
		seen := make(map[string]bool)
		for i := 0; i < 1000; i++ {
			token, err := gen.Generate()
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}
			if seen[token] {
				t.Errorf("Generate() produced duplicate token: %s", token)
			}
			seen[token] = true
		}
	})

	t.Run("rejects all-zero output", func(t *testing.T) {
		// Create a generator with a reader that returns all zeros
		zeroReader := bytes.NewReader(make([]byte, tokenBytes))
		badGen := newTokenGeneratorWithReader(zeroReader)

		_, err := badGen.Generate()
		if err != ErrRandFailure {
			t.Errorf("Generate() with all-zero reader: error = %v, want ErrRandFailure", err)
		}
	})

	t.Run("returns error on read failure", func(t *testing.T) {
		badGen := newTokenGeneratorWithReader(&failingReader{})

		_, err := badGen.Generate()
		if err != ErrRandFailure {
			t.Errorf("Generate() with failing reader: error = %v, want ErrRandFailure", err)
		}
	})
}

// TestTokenUnlinkability verifies that relay tokens are NOT derived from
// user_id or client_id — they are purely random. This is a critical privacy
// property: two RPs' addresses for the same user must be completely uncorrelated.
func TestTokenUnlinkability(t *testing.T) {
	gen := NewTokenGenerator()
	userID := uuid.New()

	t.Run("same user different RPs get uncorrelated tokens", func(t *testing.T) {
		// Generate addresses for the same user across multiple RPs
		addr1, _, err := NewAddress(gen, userID, "rp1.example.com", "user@real.com", region.EU)
		if err != nil {
			t.Fatalf("NewAddress() error = %v", err)
		}

		addr2, _, err := NewAddress(gen, userID, "rp2.example.com", "user@real.com", region.EU)
		if err != nil {
			t.Fatalf("NewAddress() error = %v", err)
		}

		// Tokens must be different (not derived from user_id)
		if addr1.Token == addr2.Token {
			t.Error("same user got same token for different RPs — tokens are NOT unlinkable!")
		}

		// Tokens should have no predictable relationship
		// (we can't prove this statistically in a unit test, but we verify they're different)
		if addr1.Token[:5] == addr2.Token[:5] {
			t.Log("warning: tokens share a common prefix, may indicate derivation pattern")
		}
	})

	t.Run("different users same RP get uncorrelated tokens", func(t *testing.T) {
		user1 := uuid.New()
		user2 := uuid.New()

		addr1, _, err := NewAddress(gen, user1, "rp.example.com", "user1@real.com", region.EU)
		if err != nil {
			t.Fatalf("NewAddress() error = %v", err)
		}

		addr2, _, err := NewAddress(gen, user2, "rp.example.com", "user2@real.com", region.EU)
		if err != nil {
			t.Fatalf("NewAddress() error = %v", err)
		}

		if addr1.Token == addr2.Token {
			t.Error("different users got same token — collision!")
		}
	})

	t.Run("tokens are not derived from inputs", func(t *testing.T) {
		// Generate many tokens for the same (user, RP) inputs and verify
		// they're all different — proving randomness, not derivation
		seen := make(map[string]bool)
		for i := 0; i < 100; i++ {
			addr, _, err := NewAddress(gen, userID, "rp.example.com", "user@real.com", region.EU)
			if err != nil {
				t.Fatalf("NewAddress() error = %v", err)
			}
			if seen[addr.Token] {
				t.Errorf("token collision on iteration %d — possible derivation pattern", i)
			}
			seen[addr.Token] = true
		}
	})
}

func TestNewAddress(t *testing.T) {
	gen := NewTokenGenerator()
	userID := uuid.New()

	t.Run("creates valid address and mapping", func(t *testing.T) {
		addr, mapping, err := NewAddress(gen, userID, "rp.example.com", "user@real.com", region.EU)
		if err != nil {
			t.Fatalf("NewAddress() error = %v", err)
		}

		// Verify address fields
		if addr.ID == uuid.Nil {
			t.Error("address ID is nil")
		}
		if addr.Token == "" {
			t.Error("address token is empty")
		}
		if addr.UserID != userID {
			t.Errorf("address UserID = %v, want %v", addr.UserID, userID)
		}
		if addr.ClientID != "rp.example.com" {
			t.Errorf("address ClientID = %v, want rp.example.com", addr.ClientID)
		}
		if addr.State != StateActive {
			t.Errorf("address State = %v, want %v", addr.State, StateActive)
		}
		if addr.Region != region.EU {
			t.Errorf("address Region = %v, want %v", addr.Region, region.EU)
		}
		if addr.CreatedAt.IsZero() {
			t.Error("address CreatedAt is zero")
		}
		if addr.DeactivatedAt != nil {
			t.Error("address DeactivatedAt should be nil for new address")
		}

		// Verify mapping fields
		if mapping.RelayToken != addr.Token {
			t.Errorf("mapping RelayToken = %v, want %v", mapping.RelayToken, addr.Token)
		}
		if mapping.RealEmail != "user@real.com" {
			t.Errorf("mapping RealEmail = %v, want user@real.com", mapping.RealEmail)
		}
		if mapping.UserID != userID {
			t.Errorf("mapping UserID = %v, want %v", mapping.UserID, userID)
		}
		if mapping.ClientID != "rp.example.com" {
			t.Errorf("mapping ClientID = %v, want rp.example.com", mapping.ClientID)
		}
		if mapping.Region != region.EU {
			t.Errorf("mapping Region = %v, want %v", mapping.Region, region.EU)
		}
	})

	t.Run("rejects empty user_id", func(t *testing.T) {
		_, _, err := NewAddress(gen, uuid.Nil, "rp.example.com", "user@real.com", region.EU)
		if err != ErrEmptyUserID {
			t.Errorf("NewAddress() with nil userID: error = %v, want ErrEmptyUserID", err)
		}
	})

	t.Run("rejects empty client_id", func(t *testing.T) {
		_, _, err := NewAddress(gen, userID, "", "user@real.com", region.EU)
		if err != ErrEmptyClientID {
			t.Errorf("NewAddress() with empty clientID: error = %v, want ErrEmptyClientID", err)
		}
	})

	t.Run("rejects empty email", func(t *testing.T) {
		_, _, err := NewAddress(gen, userID, "rp.example.com", "", region.EU)
		if err != ErrEmptyEmail {
			t.Errorf("NewAddress() with empty email: error = %v, want ErrEmptyEmail", err)
		}
	})

	t.Run("rejects empty region", func(t *testing.T) {
		_, _, err := NewAddress(gen, userID, "rp.example.com", "user@real.com", "")
		if err != ErrInvalidRegion {
			t.Errorf("NewAddress() with empty region: error = %v, want ErrInvalidRegion", err)
		}
	})
}

func TestFormatEmail(t *testing.T) {
	tests := []struct {
		token  string
		region region.Region
		want   string
	}{
		{"abc123", region.EU, "abc123@relay.EU.harbor.id"},
		{"xyz789", region.US, "xyz789@relay.US.harbor.id"},
		{"token", region.APAC, "token@relay.APAC.harbor.id"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatEmail(tt.token, tt.region)
			if got != tt.want {
				t.Errorf("FormatEmail(%q, %q) = %q, want %q", tt.token, tt.region, got, tt.want)
			}
		})
	}
}

func TestParseState(t *testing.T) {
	tests := []struct {
		input   string
		want    State
		wantErr bool
	}{
		{"active", StateActive, false},
		{"deactivated", StateDeactivated, false},
		{"byo_domain", StateBYODomain, false},
		{"invalid", "", true},
		{"ACTIVE", "", true}, // case-sensitive
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseState(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseState(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseState(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestAddress_IsActive(t *testing.T) {
	addr := &Address{State: StateActive}
	if !addr.IsActive() {
		t.Error("IsActive() = false for StateActive, want true")
	}

	addr.State = StateDeactivated
	if addr.IsActive() {
		t.Error("IsActive() = true for StateDeactivated, want false")
	}
}

func TestAddress_CanReceiveMail(t *testing.T) {
	tests := []struct {
		state State
		want  bool
	}{
		{StateActive, true},
		{StateDeactivated, false},
		{StateBYODomain, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			addr := &Address{State: tt.state}
			if got := addr.CanReceiveMail(); got != tt.want {
				t.Errorf("CanReceiveMail() = %v, want %v", got, tt.want)
			}
		})
	}
}

// failingReader is an io.Reader that always returns an error.
type failingReader struct{}

func (f *failingReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}
