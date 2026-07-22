package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/mileusna/spf"

	"github.com/harbor/harbor/internal/region"
)

// mockAddressLookup implements AddressLookup for testing.
type mockAddressLookup struct {
	addresses map[string]*Address
	err       error
}

func (m *mockAddressLookup) GetByToken(_ context.Context, token string) (*Address, []byte, error) {
	if m.err != nil {
		return nil, nil, m.err
	}
	addr, ok := m.addresses[token]
	if !ok {
		return nil, nil, ErrRelayAddressNotFound
	}
	return addr, []byte("encrypted-mapping"), nil
}

func newMockLookup() *mockAddressLookup {
	return &mockAddressLookup{
		addresses: make(map[string]*Address),
	}
}

func (m *mockAddressLookup) addAddress(token string, state State) {
	m.addresses[token] = &Address{
		ID:       uuid.New(),
		Token:    token,
		UserID:   uuid.New(),
		ClientID: "test-client",
		State:    state,
		Region:   region.EU,
	}
}

func TestBackend_NewSession(t *testing.T) {
	lookup := newMockLookup()
	backend := NewBackend(MTAConfig{
		Lookup: lookup,
		Domain: "relay.eu.harbor.id",
	})

	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	if session == nil {
		t.Fatal("NewSession() returned nil session")
	}
}

func TestSession_Mail(t *testing.T) {
	lookup := newMockLookup()
	backend := NewBackend(MTAConfig{
		Lookup: lookup,
		Domain: "relay.eu.harbor.id",
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	err := s.Mail("sender@example.com", nil)
	if err != nil {
		t.Fatalf("Mail() error = %v", err)
	}
	if s.from != "sender@example.com" {
		t.Errorf("Mail() from = %q, want %q", s.from, "sender@example.com")
	}
}

func TestSession_Rcpt_ActiveAddress(t *testing.T) {
	lookup := newMockLookup()
	lookup.addAddress("valid-token", StateActive)

	backend := NewBackend(MTAConfig{
		Lookup: lookup,
		Domain: "relay.eu.harbor.id",
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	err := s.Rcpt("valid-token@relay.eu.harbor.id", nil)
	if err != nil {
		t.Fatalf("Rcpt() error = %v", err)
	}
	if len(s.recipients) != 1 {
		t.Errorf("Rcpt() recipients count = %d, want 1", len(s.recipients))
	}
	if s.recipients[0].token != "valid-token" {
		t.Errorf("Rcpt() token = %q, want %q", s.recipients[0].token, "valid-token")
	}
}

func TestSession_Rcpt_BYODomainAddress(t *testing.T) {
	lookup := newMockLookup()
	lookup.addAddress("byo-token", StateBYODomain)

	backend := NewBackend(MTAConfig{
		Lookup: lookup,
		Domain: "relay.eu.harbor.id",
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	err := s.Rcpt("byo-token@relay.eu.harbor.id", nil)
	if err != nil {
		t.Fatalf("Rcpt() error = %v", err)
	}
	if len(s.recipients) != 1 {
		t.Errorf("Rcpt() recipients count = %d, want 1", len(s.recipients))
	}
}

func TestSession_Rcpt_DeactivatedAddress(t *testing.T) {
	lookup := newMockLookup()
	lookup.addAddress("deactivated-token", StateDeactivated)

	backend := NewBackend(MTAConfig{
		Lookup: lookup,
		Domain: "relay.eu.harbor.id",
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	err := s.Rcpt("deactivated-token@relay.eu.harbor.id", nil)
	if err == nil {
		t.Fatal("Rcpt() expected error for deactivated address")
	}

	var smtpErr *smtp.SMTPError
	if !errors.As(err, &smtpErr) {
		t.Fatalf("Rcpt() error is not SMTPError: %T", err)
	}
	if smtpErr.Code != 550 {
		t.Errorf("Rcpt() error code = %d, want 550", smtpErr.Code)
	}
	if !strings.Contains(smtpErr.Message, "no longer accepts mail") {
		t.Errorf("Rcpt() error message = %q, want contains 'no longer accepts mail'", smtpErr.Message)
	}
}

func TestSession_Rcpt_UnknownAddress(t *testing.T) {
	lookup := newMockLookup()
	// No addresses added

	backend := NewBackend(MTAConfig{
		Lookup: lookup,
		Domain: "relay.eu.harbor.id",
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	err := s.Rcpt("unknown-token@relay.eu.harbor.id", nil)
	if err == nil {
		t.Fatal("Rcpt() expected error for unknown address")
	}

	var smtpErr *smtp.SMTPError
	if !errors.As(err, &smtpErr) {
		t.Fatalf("Rcpt() error is not SMTPError: %T", err)
	}
	if smtpErr.Code != 550 {
		t.Errorf("Rcpt() error code = %d, want 550", smtpErr.Code)
	}
}

func TestSession_Rcpt_InvalidDomain(t *testing.T) {
	lookup := newMockLookup()
	lookup.addAddress("valid-token", StateActive)

	backend := NewBackend(MTAConfig{
		Lookup: lookup,
		Domain: "relay.eu.harbor.id",
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	// Wrong domain should be rejected
	err := s.Rcpt("valid-token@wrong-domain.com", nil)
	if err == nil {
		t.Fatal("Rcpt() expected error for wrong domain")
	}

	var smtpErr *smtp.SMTPError
	if !errors.As(err, &smtpErr) {
		t.Fatalf("Rcpt() error is not SMTPError: %T", err)
	}
	if smtpErr.Code != 550 {
		t.Errorf("Rcpt() error code = %d, want 550", smtpErr.Code)
	}
}

func TestSession_Rcpt_TooManyRecipients(t *testing.T) {
	lookup := newMockLookup()
	lookup.addAddress("token1", StateActive)
	lookup.addAddress("token2", StateActive)

	backend := NewBackend(MTAConfig{
		Lookup:        lookup,
		Domain:        "relay.eu.harbor.id",
		MaxRecipients: 1,
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	// First recipient should succeed
	err := s.Rcpt("token1@relay.eu.harbor.id", nil)
	if err != nil {
		t.Fatalf("Rcpt() first recipient error = %v", err)
	}

	// Second recipient should fail (over limit)
	err = s.Rcpt("token2@relay.eu.harbor.id", nil)
	if err == nil {
		t.Fatal("Rcpt() expected error for too many recipients")
	}

	var smtpErr *smtp.SMTPError
	if !errors.As(err, &smtpErr) {
		t.Fatalf("Rcpt() error is not SMTPError: %T", err)
	}
	if smtpErr.Code != 452 {
		t.Errorf("Rcpt() error code = %d, want 452", smtpErr.Code)
	}
}

func TestSession_Rcpt_LookupError(t *testing.T) {
	lookup := newMockLookup()
	lookup.err = errors.New("database connection failed")

	backend := NewBackend(MTAConfig{
		Lookup: lookup,
		Domain: "relay.eu.harbor.id",
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	err := s.Rcpt("any-token@relay.eu.harbor.id", nil)
	if err == nil {
		t.Fatal("Rcpt() expected error on lookup failure")
	}

	var smtpErr *smtp.SMTPError
	if !errors.As(err, &smtpErr) {
		t.Fatalf("Rcpt() error is not SMTPError: %T", err)
	}
	// Temporary failure (4xx) for database errors
	if smtpErr.Code != 451 {
		t.Errorf("Rcpt() error code = %d, want 451", smtpErr.Code)
	}
}

func TestSession_Data_Success(t *testing.T) {
	lookup := newMockLookup()
	lookup.addAddress("valid-token", StateActive)

	backend := NewBackend(MTAConfig{
		Lookup: lookup,
		Domain: "relay.eu.harbor.id",
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	// Add a valid recipient first
	err := s.Rcpt("valid-token@relay.eu.harbor.id", nil)
	if err != nil {
		t.Fatalf("Rcpt() error = %v", err)
	}

	// Send message data
	messageBody := "From: sender@example.com\r\nTo: valid-token@relay.eu.harbor.id\r\nSubject: Test\r\n\r\nHello, World!"
	err = s.Data(strings.NewReader(messageBody))
	if err != nil {
		t.Fatalf("Data() error = %v", err)
	}
}

func TestSession_Data_NoRecipients(t *testing.T) {
	lookup := newMockLookup()

	backend := NewBackend(MTAConfig{
		Lookup: lookup,
		Domain: "relay.eu.harbor.id",
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	// Try to send data without recipients
	err := s.Data(strings.NewReader("test message"))
	if err == nil {
		t.Fatal("Data() expected error with no recipients")
	}

	var smtpErr *smtp.SMTPError
	if !errors.As(err, &smtpErr) {
		t.Fatalf("Data() error is not SMTPError: %T", err)
	}
	if smtpErr.Code != 503 {
		t.Errorf("Data() error code = %d, want 503", smtpErr.Code)
	}
}

func TestSession_Reset(t *testing.T) {
	lookup := newMockLookup()
	lookup.addAddress("valid-token", StateActive)

	backend := NewBackend(MTAConfig{
		Lookup: lookup,
		Domain: "relay.eu.harbor.id",
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	// Set up some state
	s.Mail("sender@example.com", nil)
	s.Rcpt("valid-token@relay.eu.harbor.id", nil)

	if s.from == "" || len(s.recipients) == 0 {
		t.Fatal("Session state not set up correctly")
	}

	// Reset should clear state
	s.Reset()

	if s.from != "" {
		t.Errorf("Reset() from = %q, want empty", s.from)
	}
	if len(s.recipients) != 0 {
		t.Errorf("Reset() recipients count = %d, want 0", len(s.recipients))
	}
}

// Note: Auth methods are not part of go-smtp's basic Session interface.
// The Session interface only requires: Mail, Rcpt, Data, Reset, Logout.

func TestSession_ParseRecipient(t *testing.T) {
	lookup := newMockLookup()

	backend := NewBackend(MTAConfig{
		Lookup: lookup,
		Domain: "relay.eu.harbor.id",
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	tests := []struct {
		name    string
		to      string
		want    string
		wantErr bool
	}{
		{
			name:    "valid address",
			to:      "token123@relay.eu.harbor.id",
			want:    "token123",
			wantErr: false,
		},
		{
			name:    "case insensitive",
			to:      "TOKEN123@RELAY.EU.HARBOR.ID",
			want:    "token123",
			wantErr: false,
		},
		{
			name:    "with whitespace",
			to:      "  token123@relay.eu.harbor.id  ",
			want:    "token123",
			wantErr: false,
		},
		{
			name:    "wrong domain",
			to:      "token123@wrong.domain.com",
			want:    "",
			wantErr: true,
		},
		{
			name:    "no @ symbol",
			to:      "invalid-address",
			want:    "",
			wantErr: true,
		},
		{
			name:    "empty local part",
			to:      "@relay.eu.harbor.id",
			want:    "",
			wantErr: true,
		},
		{
			name:    "empty domain",
			to:      "token@",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.parseRecipient(tt.to)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRecipient(%q) error = %v, wantErr %v", tt.to, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseRecipient(%q) = %q, want %q", tt.to, got, tt.want)
			}
		})
	}
}

func TestNewBackend_Defaults(t *testing.T) {
	lookup := newMockLookup()

	backend := NewBackend(MTAConfig{
		Lookup: lookup,
	})

	// Check defaults are applied
	if backend.maxRecipients != 1 {
		t.Errorf("maxRecipients = %d, want 1", backend.maxRecipients)
	}
	if backend.maxMsgBytes != 25*1024*1024 {
		t.Errorf("maxMsgBytes = %d, want %d", backend.maxMsgBytes, 25*1024*1024)
	}
	if backend.logger == nil {
		t.Error("logger is nil, want non-nil")
	}
}

func TestNewServer(t *testing.T) {
	lookup := newMockLookup()

	server := NewServer(MTAConfig{
		Lookup:          lookup,
		Domain:          "relay.eu.harbor.id",
		MaxRecipients:   5,
		MaxMessageBytes: 10 * 1024 * 1024,
	})

	if server == nil {
		t.Fatal("NewServer() returned nil")
	}
	if server.Domain != "relay.eu.harbor.id" {
		t.Errorf("server.Domain = %q, want %q", server.Domain, "relay.eu.harbor.id")
	}
	if server.MaxRecipients != 5 {
		t.Errorf("server.MaxRecipients = %d, want 5", server.MaxRecipients)
	}
	if server.MaxMessageBytes != 10*1024*1024 {
		t.Errorf("server.MaxMessageBytes = %d, want %d", server.MaxMessageBytes, 10*1024*1024)
	}
}

// TestSession_Rcpt_CaseInsensitiveToken verifies that token lookup preserves
// case sensitivity while domain matching is case-insensitive.
func TestSession_Rcpt_CaseInsensitiveToken(t *testing.T) {
	lookup := newMockLookup()
	// Add token in lowercase (as stored)
	lookup.addAddress("mytoken", StateActive)

	backend := NewBackend(MTAConfig{
		Lookup: lookup,
		Domain: "relay.eu.harbor.id",
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	// The parseRecipient lowercases the entire address, so MYTOKEN becomes mytoken
	err := s.Rcpt("MYTOKEN@RELAY.EU.HARBOR.ID", nil)
	if err != nil {
		t.Fatalf("Rcpt() error = %v", err)
	}
	if len(s.recipients) != 1 {
		t.Errorf("Rcpt() recipients count = %d, want 1", len(s.recipients))
	}
}

// mtaFailingReader is an io.Reader that always returns an error.
// Named differently from failingReader in address_test.go to avoid redeclaration.
type mtaFailingReader struct{}

func (f *mtaFailingReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

func TestSession_Data_ReadError(t *testing.T) {
	lookup := newMockLookup()
	lookup.addAddress("valid-token", StateActive)

	backend := NewBackend(MTAConfig{
		Lookup: lookup,
		Domain: "relay.eu.harbor.id",
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	// Add a valid recipient first
	err := s.Rcpt("valid-token@relay.eu.harbor.id", nil)
	if err != nil {
		t.Fatalf("Rcpt() error = %v", err)
	}

	// Try to read from failing reader
	err = s.Data(&mtaFailingReader{})
	if err == nil {
		t.Fatal("Data() expected error on read failure")
	}

	var smtpErr *smtp.SMTPError
	if !errors.As(err, &smtpErr) {
		t.Fatalf("Data() error is not SMTPError: %T", err)
	}
	if smtpErr.Code != 451 {
		t.Errorf("Data() error code = %d, want 451", smtpErr.Code)
	}
}

// TestSession_Data_WithAuthenticator tests that authentication is invoked when
// an Authenticator is configured on the backend.
func TestSession_Data_WithAuthenticator(t *testing.T) {
	lookup := newMockLookup()
	lookup.addAddress("valid-token", StateActive)

	// Create an authenticator with stubs that return pass for everything
	auth := newAuthenticatorWithResolvers(
		func(_ net.IP, _, _, _ string) spf.Result { return spf.Pass },
		buildLookupTXT(map[string][]string{
			"_dmarc.example.com": {"v=DMARC1; p=none"},
		}),
	)

	backend := NewBackend(MTAConfig{
		Lookup:        lookup,
		Domain:        "relay.eu.harbor.id",
		Authenticator: auth,
		EnforceAuth:   false, // monitoring mode
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	// Set connection info directly (no real connection in unit tests)
	s.remoteIP = net.ParseIP("192.0.2.1")
	s.helo = "mail.example.com"

	s.Mail("sender@example.com", nil)
	err := s.Rcpt("valid-token@relay.eu.harbor.id", nil)
	if err != nil {
		t.Fatalf("Rcpt() error = %v", err)
	}

	messageBody := "From: sender@example.com\r\nTo: valid-token@relay.eu.harbor.id\r\nSubject: Test\r\n\r\nHello, World!"
	err = s.Data(strings.NewReader(messageBody))
	if err != nil {
		t.Fatalf("Data() error = %v", err)
	}
}

// TestSession_Data_AuthReject tests that messages are rejected when
// authentication fails and EnforceAuth is true.
func TestSession_Data_AuthReject(t *testing.T) {
	lookup := newMockLookup()
	lookup.addAddress("valid-token", StateActive)

	// Create an authenticator that fails SPF and has no DMARC record
	auth := newAuthenticatorWithResolvers(
		func(_ net.IP, _, _, _ string) spf.Result { return spf.Fail },
		buildLookupTXT(map[string][]string{}), // No DMARC record
	)

	backend := NewBackend(MTAConfig{
		Lookup:        lookup,
		Domain:        "relay.eu.harbor.id",
		Authenticator: auth,
		EnforceAuth:   true, // enforcement mode
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	s.remoteIP = net.ParseIP("192.0.2.1")
	s.helo = "mail.example.com"

	s.Mail("sender@example.com", nil)
	err := s.Rcpt("valid-token@relay.eu.harbor.id", nil)
	if err != nil {
		t.Fatalf("Rcpt() error = %v", err)
	}

	messageBody := "From: sender@example.com\r\nTo: valid-token@relay.eu.harbor.id\r\nSubject: Test\r\n\r\nHello, World!"
	err = s.Data(strings.NewReader(messageBody))
	if err == nil {
		t.Fatal("Data() expected error for failed authentication")
	}

	var smtpErr *smtp.SMTPError
	if !errors.As(err, &smtpErr) {
		t.Fatalf("Data() error is not SMTPError: %T", err)
	}
	if smtpErr.Code != 550 {
		t.Errorf("Data() error code = %d, want 550", smtpErr.Code)
	}
	if !strings.Contains(smtpErr.Message, "authentication") {
		t.Errorf("Data() error message = %q, want contains 'authentication'", smtpErr.Message)
	}
}

// TestSession_Data_AuthMonitoringMode tests that messages are accepted even
// when authentication fails if EnforceAuth is false (monitoring mode).
func TestSession_Data_AuthMonitoringMode(t *testing.T) {
	lookup := newMockLookup()
	lookup.addAddress("valid-token", StateActive)

	// Create an authenticator that fails SPF
	auth := newAuthenticatorWithResolvers(
		func(_ net.IP, _, _, _ string) spf.Result { return spf.Fail },
		buildLookupTXT(map[string][]string{}),
	)

	backend := NewBackend(MTAConfig{
		Lookup:        lookup,
		Domain:        "relay.eu.harbor.id",
		Authenticator: auth,
		EnforceAuth:   false, // monitoring mode — should accept anyway
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	s.remoteIP = net.ParseIP("192.0.2.1")
	s.helo = "mail.example.com"

	s.Mail("sender@example.com", nil)
	err := s.Rcpt("valid-token@relay.eu.harbor.id", nil)
	if err != nil {
		t.Fatalf("Rcpt() error = %v", err)
	}

	messageBody := "From: sender@example.com\r\nTo: valid-token@relay.eu.harbor.id\r\nSubject: Test\r\n\r\nHello, World!"
	err = s.Data(strings.NewReader(messageBody))
	if err != nil {
		t.Fatalf("Data() error = %v, want nil (monitoring mode)", err)
	}
}
