package relay

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/harbor-auth/harbor/internal/region"
)

// mockDNSResolver implements DNSResolver for testing.
type mockDNSResolver struct {
	txtRecords   map[string][]string
	mxRecords    map[string][]*net.MX
	cnameRecords map[string]string
	txtErr       error
	mxErr        error
	cnameErr     error
}

func newMockDNSResolver() *mockDNSResolver {
	return &mockDNSResolver{
		txtRecords:   make(map[string][]string),
		mxRecords:    make(map[string][]*net.MX),
		cnameRecords: make(map[string]string),
	}
}

func (m *mockDNSResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if m.txtErr != nil {
		return nil, m.txtErr
	}
	if records, ok := m.txtRecords[name]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (m *mockDNSResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if m.mxErr != nil {
		return nil, m.mxErr
	}
	if records, ok := m.mxRecords[name]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (m *mockDNSResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if m.cnameErr != nil {
		return "", m.cnameErr
	}
	if cname, ok := m.cnameRecords[host]; ok {
		return cname, nil
	}
	return "", &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestGenerateChallenge(t *testing.T) {
	userID := uuid.New()

	t.Run("creates valid challenge", func(t *testing.T) {
		domain, err := GenerateChallenge(userID, "mail.example.com", region.EU)
		if err != nil {
			t.Fatalf("GenerateChallenge() error = %v", err)
		}

		if domain.ID == uuid.Nil {
			t.Error("domain.ID is nil")
		}
		if domain.Domain != "mail.example.com" {
			t.Errorf("domain.Domain = %q, want %q", domain.Domain, "mail.example.com")
		}
		if domain.UserID != userID {
			t.Errorf("domain.UserID = %v, want %v", domain.UserID, userID)
		}
		if domain.ChallengeToken == "" {
			t.Error("domain.ChallengeToken is empty")
		}
		// 32 bytes base64url encoded = 43 characters (no padding)
		if len(domain.ChallengeToken) != 43 {
			t.Errorf("domain.ChallengeToken length = %d, want 43", len(domain.ChallengeToken))
		}
		if domain.State != BYODomainStatePending {
			t.Errorf("domain.State = %v, want %v", domain.State, BYODomainStatePending)
		}
		if domain.Region != region.EU {
			t.Errorf("domain.Region = %v, want %v", domain.Region, region.EU)
		}
		if domain.CreatedAt.IsZero() {
			t.Error("domain.CreatedAt is zero")
		}
		if domain.VerifiedAt != nil {
			t.Error("domain.VerifiedAt should be nil for new challenge")
		}
		if domain.ExpiresAt.Before(domain.CreatedAt) {
			t.Error("domain.ExpiresAt should be after CreatedAt")
		}
		// Expiry should be ~72 hours from creation
		expectedExpiry := domain.CreatedAt.Add(72 * time.Hour)
		if domain.ExpiresAt.Sub(expectedExpiry) > time.Second {
			t.Errorf("domain.ExpiresAt = %v, want ~%v", domain.ExpiresAt, expectedExpiry)
		}
	})

	t.Run("normalizes domain to lowercase", func(t *testing.T) {
		domain, err := GenerateChallenge(userID, "MAIL.EXAMPLE.COM", region.EU)
		if err != nil {
			t.Fatalf("GenerateChallenge() error = %v", err)
		}
		if domain.Domain != "mail.example.com" {
			t.Errorf("domain.Domain = %q, want %q", domain.Domain, "mail.example.com")
		}
	})

	t.Run("trims whitespace", func(t *testing.T) {
		domain, err := GenerateChallenge(userID, "  mail.example.com  ", region.EU)
		if err != nil {
			t.Fatalf("GenerateChallenge() error = %v", err)
		}
		if domain.Domain != "mail.example.com" {
			t.Errorf("domain.Domain = %q, want %q", domain.Domain, "mail.example.com")
		}
	})

	t.Run("rejects empty user ID", func(t *testing.T) {
		_, err := GenerateChallenge(uuid.Nil, "mail.example.com", region.EU)
		if !errors.Is(err, ErrEmptyUserID) {
			t.Errorf("GenerateChallenge() error = %v, want ErrEmptyUserID", err)
		}
	})

	t.Run("rejects empty domain", func(t *testing.T) {
		_, err := GenerateChallenge(userID, "", region.EU)
		if !errors.Is(err, ErrDomainEmpty) {
			t.Errorf("GenerateChallenge() error = %v, want ErrDomainEmpty", err)
		}
	})

	t.Run("rejects invalid domain", func(t *testing.T) {
		testCases := []string{
			"nodot",
			".leading.dot",
			"trailing.dot.",
			"-leading-hyphen.com",
			"trailing-hyphen-.com",
			"has spaces.com",
			"has\ttab.com",
			"double..dot.com",
		}
		for _, tc := range testCases {
			_, err := GenerateChallenge(userID, tc, region.EU)
			if !errors.Is(err, ErrDomainInvalid) {
				t.Errorf("GenerateChallenge(%q) error = %v, want ErrDomainInvalid", tc, err)
			}
		}
	})

	t.Run("rejects empty region", func(t *testing.T) {
		_, err := GenerateChallenge(userID, "mail.example.com", "")
		if !errors.Is(err, ErrInvalidRegion) {
			t.Errorf("GenerateChallenge() error = %v, want ErrInvalidRegion", err)
		}
	})

	t.Run("generates unique tokens", func(t *testing.T) {
		seen := make(map[string]bool)
		for i := 0; i < 100; i++ {
			domain, err := GenerateChallenge(userID, "mail.example.com", region.EU)
			if err != nil {
				t.Fatalf("GenerateChallenge() error = %v", err)
			}
			if seen[domain.ChallengeToken] {
				t.Errorf("duplicate token generated on iteration %d", i)
			}
			seen[domain.ChallengeToken] = true
		}
	})
}

func TestDomainVerifier_VerifyTXTChallenge(t *testing.T) {
	userID := uuid.New()
	resolver := newMockDNSResolver()
	verifier := NewDomainVerifier(resolver, "mta-eu.harbor.id", "relay.eu.harbor.id")

	t.Run("verifies correct TXT record", func(t *testing.T) {
		domain, _ := GenerateChallenge(userID, "mail.example.com", region.EU)

		// Set up the mock to return the correct TXT record
		txtHost := "_harbor-verify.mail.example.com"
		resolver.txtRecords[txtHost] = []string{"harbor-verify=" + domain.ChallengeToken}

		err := verifier.VerifyTXTChallenge(context.Background(), domain)
		if err != nil {
			t.Fatalf("VerifyTXTChallenge() error = %v", err)
		}
		if domain.State != BYODomainStateVerified {
			t.Errorf("domain.State = %v, want %v", domain.State, BYODomainStateVerified)
		}
		if domain.VerifiedAt == nil {
			t.Error("domain.VerifiedAt should be set")
		}
	})

	t.Run("handles TXT record with whitespace", func(t *testing.T) {
		domain, _ := GenerateChallenge(userID, "whitespace.example.com", region.EU)

		txtHost := "_harbor-verify.whitespace.example.com"
		resolver.txtRecords[txtHost] = []string{"  harbor-verify=" + domain.ChallengeToken + "  "}

		err := verifier.VerifyTXTChallenge(context.Background(), domain)
		if err != nil {
			t.Fatalf("VerifyTXTChallenge() error = %v", err)
		}
		if domain.State != BYODomainStateVerified {
			t.Errorf("domain.State = %v, want %v", domain.State, BYODomainStateVerified)
		}
	})

	t.Run("returns error for missing TXT record", func(t *testing.T) {
		domain, _ := GenerateChallenge(userID, "notxt.example.com", region.EU)
		// Don't set up any TXT records for this domain

		err := verifier.VerifyTXTChallenge(context.Background(), domain)
		if !errors.Is(err, ErrTXTRecordNotFound) {
			t.Errorf("VerifyTXTChallenge() error = %v, want ErrTXTRecordNotFound", err)
		}
	})

	t.Run("returns error for wrong TXT record value", func(t *testing.T) {
		domain, _ := GenerateChallenge(userID, "wrong.example.com", region.EU)

		txtHost := "_harbor-verify.wrong.example.com"
		resolver.txtRecords[txtHost] = []string{"harbor-verify=wrong-token"}

		err := verifier.VerifyTXTChallenge(context.Background(), domain)
		if !errors.Is(err, ErrTXTRecordMismatch) {
			t.Errorf("VerifyTXTChallenge() error = %v, want ErrTXTRecordMismatch", err)
		}
	})

	t.Run("returns error for expired challenge", func(t *testing.T) {
		domain, _ := GenerateChallenge(userID, "expired.example.com", region.EU)
		domain.ExpiresAt = time.Now().Add(-1 * time.Hour) // Expired

		err := verifier.VerifyTXTChallenge(context.Background(), domain)
		if !errors.Is(err, ErrChallengeExpired) {
			t.Errorf("VerifyTXTChallenge() error = %v, want ErrChallengeExpired", err)
		}
	})

	t.Run("returns error for non-pending domain", func(t *testing.T) {
		domain, _ := GenerateChallenge(userID, "verified.example.com", region.EU)
		domain.State = BYODomainStateVerified

		err := verifier.VerifyTXTChallenge(context.Background(), domain)
		if !errors.Is(err, ErrChallengeNotFound) {
			t.Errorf("VerifyTXTChallenge() error = %v, want ErrChallengeNotFound", err)
		}
	})

	t.Run("finds correct record among multiple TXT records", func(t *testing.T) {
		domain, _ := GenerateChallenge(userID, "multi.example.com", region.EU)

		txtHost := "_harbor-verify.multi.example.com"
		resolver.txtRecords[txtHost] = []string{
			"some-other-record",
			"harbor-verify=" + domain.ChallengeToken,
			"another-record",
		}

		err := verifier.VerifyTXTChallenge(context.Background(), domain)
		if err != nil {
			t.Fatalf("VerifyTXTChallenge() error = %v", err)
		}
		if domain.State != BYODomainStateVerified {
			t.Errorf("domain.State = %v, want %v", domain.State, BYODomainStateVerified)
		}
	})
}

func TestDomainVerifier_ValidateDNSSetup(t *testing.T) {
	resolver := newMockDNSResolver()
	verifier := NewDomainVerifier(resolver, "mta-eu.harbor.id", "relay.eu.harbor.id")

	t.Run("validates complete DNS setup", func(t *testing.T) {
		domain := "complete.example.com"

		// Set up MX records
		resolver.mxRecords[domain] = []*net.MX{
			{Host: "mta-eu.harbor.id.", Pref: 10},
		}

		// Set up SPF record
		resolver.txtRecords[domain] = []string{
			"v=spf1 include:relay.eu.harbor.id ~all",
		}

		// Set up DKIM CNAME
		dkimHost := "harbor._domainkey." + domain
		resolver.cnameRecords[dkimHost] = "harbor._domainkey.relay.eu.harbor.id."

		status, err := verifier.ValidateDNSSetup(context.Background(), domain)
		if err != nil {
			t.Fatalf("ValidateDNSSetup() error = %v", err)
		}
		if !status.AllValid {
			t.Error("status.AllValid = false, want true")
		}
		if !status.MXValid {
			t.Error("status.MXValid = false, want true")
		}
		if !status.SPFValid {
			t.Error("status.SPFValid = false, want true")
		}
		if !status.DKIMValid {
			t.Error("status.DKIMValid = false, want true")
		}
	})

	t.Run("detects missing MX record", func(t *testing.T) {
		domain := "nomx.example.com"

		// Set up SPF and DKIM but not MX
		resolver.txtRecords[domain] = []string{"v=spf1 include:relay.eu.harbor.id ~all"}
		dkimHost := "harbor._domainkey." + domain
		resolver.cnameRecords[dkimHost] = "harbor._domainkey.relay.eu.harbor.id."

		status, err := verifier.ValidateDNSSetup(context.Background(), domain)
		if err != nil {
			t.Fatalf("ValidateDNSSetup() error = %v", err)
		}
		if status.AllValid {
			t.Error("status.AllValid = true, want false (missing MX)")
		}
		if status.MXValid {
			t.Error("status.MXValid = true, want false")
		}
	})

	t.Run("detects wrong MX record", func(t *testing.T) {
		domain := "wrongmx.example.com"

		resolver.mxRecords[domain] = []*net.MX{
			{Host: "mail.google.com.", Pref: 10},
		}
		resolver.txtRecords[domain] = []string{"v=spf1 include:relay.eu.harbor.id ~all"}
		dkimHost := "harbor._domainkey." + domain
		resolver.cnameRecords[dkimHost] = "harbor._domainkey.relay.eu.harbor.id."

		status, err := verifier.ValidateDNSSetup(context.Background(), domain)
		if err != nil {
			t.Fatalf("ValidateDNSSetup() error = %v", err)
		}
		if status.MXValid {
			t.Error("status.MXValid = true, want false (wrong MX)")
		}
		if len(status.MXRecords) == 0 {
			t.Error("status.MXRecords should contain the found records")
		}
	})

	t.Run("detects missing SPF record", func(t *testing.T) {
		domain := "nospf.example.com"

		resolver.mxRecords[domain] = []*net.MX{{Host: "mta-eu.harbor.id.", Pref: 10}}
		// No TXT records for SPF
		dkimHost := "harbor._domainkey." + domain
		resolver.cnameRecords[dkimHost] = "harbor._domainkey.relay.eu.harbor.id."

		status, err := verifier.ValidateDNSSetup(context.Background(), domain)
		if err != nil {
			t.Fatalf("ValidateDNSSetup() error = %v", err)
		}
		if status.SPFValid {
			t.Error("status.SPFValid = true, want false")
		}
	})

	t.Run("detects invalid SPF record", func(t *testing.T) {
		domain := "badspf.example.com"

		resolver.mxRecords[domain] = []*net.MX{{Host: "mta-eu.harbor.id.", Pref: 10}}
		resolver.txtRecords[domain] = []string{"v=spf1 include:other-domain.com ~all"} // Wrong include
		dkimHost := "harbor._domainkey." + domain
		resolver.cnameRecords[dkimHost] = "harbor._domainkey.relay.eu.harbor.id."

		status, err := verifier.ValidateDNSSetup(context.Background(), domain)
		if err != nil {
			t.Fatalf("ValidateDNSSetup() error = %v", err)
		}
		if status.SPFValid {
			t.Error("status.SPFValid = true, want false (wrong include)")
		}
		if status.SPFRecord == "" {
			t.Error("status.SPFRecord should contain the found record")
		}
	})

	t.Run("detects missing DKIM record", func(t *testing.T) {
		domain := "nodkim.example.com"

		resolver.mxRecords[domain] = []*net.MX{{Host: "mta-eu.harbor.id.", Pref: 10}}
		resolver.txtRecords[domain] = []string{"v=spf1 include:relay.eu.harbor.id ~all"}
		// No DKIM records

		status, err := verifier.ValidateDNSSetup(context.Background(), domain)
		if err != nil {
			t.Fatalf("ValidateDNSSetup() error = %v", err)
		}
		if status.DKIMValid {
			t.Error("status.DKIMValid = true, want false")
		}
	})

	t.Run("accepts DKIM TXT record instead of CNAME", func(t *testing.T) {
		domain := "dkimtxt.example.com"

		resolver.mxRecords[domain] = []*net.MX{{Host: "mta-eu.harbor.id.", Pref: 10}}
		resolver.txtRecords[domain] = []string{"v=spf1 include:relay.eu.harbor.id ~all"}

		// DKIM as TXT record instead of CNAME
		dkimHost := "harbor._domainkey." + domain
		resolver.txtRecords[dkimHost] = []string{"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."}

		status, err := verifier.ValidateDNSSetup(context.Background(), domain)
		if err != nil {
			t.Fatalf("ValidateDNSSetup() error = %v", err)
		}
		if !status.DKIMValid {
			t.Error("status.DKIMValid = false, want true (TXT record should be accepted)")
		}
	})

	t.Run("normalizes domain input", func(t *testing.T) {
		domain := "  NORMALIZE.EXAMPLE.COM  "
		normalizedDomain := "normalize.example.com"

		resolver.mxRecords[normalizedDomain] = []*net.MX{{Host: "mta-eu.harbor.id.", Pref: 10}}
		resolver.txtRecords[normalizedDomain] = []string{"v=spf1 include:relay.eu.harbor.id ~all"}
		dkimHost := "harbor._domainkey." + normalizedDomain
		resolver.cnameRecords[dkimHost] = "harbor._domainkey.relay.eu.harbor.id."

		status, err := verifier.ValidateDNSSetup(context.Background(), domain)
		if err != nil {
			t.Fatalf("ValidateDNSSetup() error = %v", err)
		}
		if !status.AllValid {
			t.Error("status.AllValid = false, want true")
		}
	})
}

func TestBYODomain_StateTransitions(t *testing.T) {
	userID := uuid.New()

	t.Run("new domain starts pending", func(t *testing.T) {
		domain, _ := GenerateChallenge(userID, "test.example.com", region.EU)
		if !domain.IsPending() {
			t.Error("new domain IsPending() = false, want true")
		}
		if domain.IsVerified() {
			t.Error("new domain IsVerified() = true, want false")
		}
		if domain.IsActive() {
			t.Error("new domain IsActive() = true, want false")
		}
	})

	t.Run("activate requires verified state", func(t *testing.T) {
		domain, _ := GenerateChallenge(userID, "test.example.com", region.EU)

		// Try to activate from pending state
		err := domain.ActivateDomain()
		if err == nil {
			t.Error("ActivateDomain() from pending should return error")
		}

		// Transition to verified
		domain.State = BYODomainStateVerified

		// Now activate should work
		err = domain.ActivateDomain()
		if err != nil {
			t.Fatalf("ActivateDomain() from verified error = %v", err)
		}
		if !domain.IsActive() {
			t.Error("after ActivateDomain() IsActive() = false, want true")
		}
	})

	t.Run("mark failed transitions to failed state", func(t *testing.T) {
		domain, _ := GenerateChallenge(userID, "test.example.com", region.EU)
		domain.MarkFailed()
		if domain.State != BYODomainStateFailed {
			t.Errorf("after MarkFailed() State = %v, want %v", domain.State, BYODomainStateFailed)
		}
	})
}

func TestBYODomain_GetInstructions(t *testing.T) {
	userID := uuid.New()

	t.Run("TXT record instructions", func(t *testing.T) {
		domain, _ := GenerateChallenge(userID, "test.example.com", region.EU)
		instructions := domain.GetTXTRecordInstructions()

		expected := "_harbor-verify.test.example.com IN TXT \"harbor-verify=" + domain.ChallengeToken + "\""
		if instructions != expected {
			t.Errorf("GetTXTRecordInstructions() = %q, want %q", instructions, expected)
		}
	})

	t.Run("MX record instructions", func(t *testing.T) {
		instructions := GetMXRecordInstructions("test.example.com", "mta-eu.harbor.id")
		expected := "test.example.com IN MX 10 mta-eu.harbor.id."
		if instructions != expected {
			t.Errorf("GetMXRecordInstructions() = %q, want %q", instructions, expected)
		}
	})

	t.Run("SPF record instructions", func(t *testing.T) {
		instructions := GetSPFRecordInstructions("test.example.com", "relay.eu.harbor.id")
		expected := "test.example.com IN TXT \"v=spf1 include:relay.eu.harbor.id ~all\""
		if instructions != expected {
			t.Errorf("GetSPFRecordInstructions() = %q, want %q", instructions, expected)
		}
	})

	t.Run("DKIM record instructions", func(t *testing.T) {
		instructions := GetDKIMRecordInstructions("test.example.com", "relay.eu.harbor.id")
		expected := "harbor._domainkey.test.example.com IN CNAME harbor._domainkey.relay.eu.harbor.id."
		if instructions != expected {
			t.Errorf("GetDKIMRecordInstructions() = %q, want %q", instructions, expected)
		}
	})
}

func TestParseBYODomainState(t *testing.T) {
	tests := []struct {
		input   string
		want    BYODomainState
		wantErr bool
	}{
		{"pending", BYODomainStatePending, false},
		{"verified", BYODomainStateVerified, false},
		{"active", BYODomainStateActive, false},
		{"failed", BYODomainStateFailed, false},
		{"invalid", "", true},
		{"PENDING", "", true}, // case-sensitive
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseBYODomainState(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseBYODomainState(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseBYODomainState(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsValidDomain(t *testing.T) {
	validDomains := []string{
		"example.com",
		"mail.example.com",
		"sub.domain.example.com",
		"a.b",
		"test-domain.com",
		"123.456.com",
	}

	invalidDomains := []string{
		"",
		"nodot",
		".leading.dot",
		"trailing.dot.",
		"-leading-hyphen.com",
		"trailing-hyphen-.com",
		"has spaces.com",
		"has\ttab.com",
		"double..dot.com",
		"a",
		"..",
	}

	for _, domain := range validDomains {
		if !isValidDomain(domain) {
			t.Errorf("isValidDomain(%q) = false, want true", domain)
		}
	}

	for _, domain := range invalidDomains {
		if isValidDomain(domain) {
			t.Errorf("isValidDomain(%q) = true, want false", domain)
		}
	}
}

// TestDNSLookupErrors tests error handling for DNS lookup failures.
func TestDNSLookupErrors(t *testing.T) {
	resolver := newMockDNSResolver()
	verifier := NewDomainVerifier(resolver, "mta-eu.harbor.id", "relay.eu.harbor.id")

	t.Run("handles DNS lookup failure for TXT", func(t *testing.T) {
		userID := uuid.New()
		domain, _ := GenerateChallenge(userID, "dnsfail.example.com", region.EU)

		resolver.txtErr = errors.New("network error")
		defer func() { resolver.txtErr = nil }()

		err := verifier.VerifyTXTChallenge(context.Background(), domain)
		if !errors.Is(err, ErrDNSLookupFailed) {
			t.Errorf("VerifyTXTChallenge() error = %v, want ErrDNSLookupFailed", err)
		}
	})

	t.Run("handles DNS lookup failure for MX", func(t *testing.T) {
		resolver.mxErr = errors.New("network error")
		defer func() { resolver.mxErr = nil }()

		_, err := verifier.ValidateDNSSetup(context.Background(), "mxfail.example.com")
		if !errors.Is(err, ErrDNSLookupFailed) {
			t.Errorf("ValidateDNSSetup() error = %v, want ErrDNSLookupFailed", err)
		}
	})
}

// TestNetResolver ensures the production resolver compiles and has the right methods.
func TestNetResolver(t *testing.T) {
	resolver := NewNetResolver()
	if resolver == nil {
		t.Fatal("NewNetResolver() returned nil")
	}
	// Just verify it implements the interface
	var _ DNSResolver = resolver
}
