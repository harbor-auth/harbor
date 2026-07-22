package relay

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/harbor-auth/harbor/internal/region"
)

// BYO-domain verification constants.
const (
	// challengeTokenBytes is the number of random bytes in a TXT challenge token.
	// 32 bytes = 256 bits of entropy, yielding a 43-char base64url string.
	challengeTokenBytes = 32

	// txtRecordPrefix is the subdomain prefix for the TXT verification record.
	// Users create: _harbor-verify.<domain> IN TXT "harbor-verify=<token>"
	txtRecordPrefix = "_harbor-verify"

	// txtValuePrefix is the prefix expected in the TXT record value.
	txtValuePrefix = "harbor-verify="

	// challengeValidityDuration is how long a challenge token remains valid.
	challengeValidityDuration = 72 * time.Hour
)

// BYODomainState represents the lifecycle state of a BYO-domain.
type BYODomainState string

const (
	// BYODomainStatePending means the challenge has been issued but not yet verified.
	BYODomainStatePending BYODomainState = "pending"
	// BYODomainStateVerified means the TXT challenge has been verified.
	BYODomainStateVerified BYODomainState = "verified"
	// BYODomainStateActive means MX/SPF/DKIM setup is complete and the domain is live.
	BYODomainStateActive BYODomainState = "active"
	// BYODomainStateFailed means verification failed (e.g., wrong TXT record).
	BYODomainStateFailed BYODomainState = "failed"
)

// BYO-domain errors.
var (
	ErrDomainEmpty         = errors.New("relay: domain must be non-empty")
	ErrDomainInvalid       = errors.New("relay: invalid domain format")
	ErrDomainNotFound      = errors.New("relay: domain not found")
	ErrDomainAlreadyExists = errors.New("relay: domain already registered")
	ErrChallengeExpired    = errors.New("relay: challenge token has expired")
	ErrChallengeNotFound   = errors.New("relay: no pending challenge for domain")
	ErrTXTRecordNotFound   = errors.New("relay: TXT record not found")
	ErrTXTRecordMismatch   = errors.New("relay: TXT record does not match challenge")
	ErrMXRecordNotFound    = errors.New("relay: MX record not found")
	ErrMXRecordInvalid     = errors.New("relay: MX record does not point to Harbor")
	ErrSPFRecordNotFound   = errors.New("relay: SPF record not found")
	ErrSPFRecordInvalid    = errors.New("relay: SPF record does not include Harbor")
	ErrDKIMRecordNotFound  = errors.New("relay: DKIM record not found")
	ErrDKIMRecordInvalid   = errors.New("relay: DKIM record is invalid")
	ErrDNSLookupFailed     = errors.New("relay: DNS lookup failed")
	ErrChallengeGenFailed  = errors.New("relay: failed to generate challenge token")
)

// BYODomain represents a user's custom domain for email relay.
type BYODomain struct {
	// ID is the database primary key (UUID).
	ID uuid.UUID

	// Domain is the custom domain (e.g., "mail.alice.example").
	Domain string

	// UserID is the user who owns this domain.
	UserID uuid.UUID

	// ChallengeToken is the random token the user must publish in their TXT record.
	ChallengeToken string

	// State is the current verification state.
	State BYODomainState

	// Region is the user's home region. The domain stays region-pinned.
	Region region.Region

	// CreatedAt is when the domain verification was initiated.
	CreatedAt time.Time

	// VerifiedAt is when the TXT challenge was verified (nil if pending).
	VerifiedAt *time.Time

	// ExpiresAt is when the challenge token expires (only relevant for pending state).
	ExpiresAt time.Time
}

// DNSSetupStatus holds the results of MX/SPF/DKIM validation for a BYO-domain.
type DNSSetupStatus struct {
	// MXValid is true if the domain's MX records point to Harbor's regional MTA.
	MXValid bool
	// MXRecords are the actual MX records found (for debugging).
	MXRecords []string

	// SPFValid is true if the domain's SPF record includes Harbor's relay domain.
	SPFValid bool
	// SPFRecord is the actual SPF record found (for debugging).
	SPFRecord string

	// DKIMValid is true if the DKIM CNAME/TXT record is correctly configured.
	DKIMValid bool
	// DKIMRecord is the actual DKIM record found (for debugging).
	DKIMRecord string

	// AllValid is true if all DNS records are correctly configured.
	AllValid bool
}

// DNSResolver is the interface for DNS lookups, allowing injection for testing.
type DNSResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// NetResolver wraps net.Resolver to implement DNSResolver.
type NetResolver struct {
	resolver *net.Resolver
}

// NewNetResolver creates a DNSResolver using the default system resolver.
func NewNetResolver() *NetResolver {
	return &NetResolver{resolver: net.DefaultResolver}
}

// LookupTXT performs a DNS TXT lookup.
func (r *NetResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.resolver.LookupTXT(ctx, name)
}

// LookupMX performs a DNS MX lookup.
func (r *NetResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return r.resolver.LookupMX(ctx, name)
}

// LookupCNAME performs a DNS CNAME lookup.
func (r *NetResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return r.resolver.LookupCNAME(ctx, host)
}

// DomainVerifier handles BYO-domain TXT challenge verification and DNS setup validation.
type DomainVerifier struct {
	resolver    DNSResolver
	mtaDomain   string // e.g., "mta-eu.harbor.id" for EU region
	relayDomain string // e.g., "relay.EU.harbor.id"
}

// NewDomainVerifier creates a DomainVerifier with the given DNS resolver and
// regional MTA/relay domain configuration.
func NewDomainVerifier(resolver DNSResolver, mtaDomain, relayDomain string) *DomainVerifier {
	return &DomainVerifier{
		resolver:    resolver,
		mtaDomain:   strings.ToLower(mtaDomain),
		relayDomain: strings.ToLower(relayDomain),
	}
}

// GenerateChallenge creates a new BYODomain with a fresh challenge token.
// The user must publish this token as a TXT record to prove domain ownership.
func GenerateChallenge(userID uuid.UUID, domain string, reg region.Region) (*BYODomain, error) {
	if userID == uuid.Nil {
		return nil, ErrEmptyUserID
	}
	if domain == "" {
		return nil, ErrDomainEmpty
	}
	if !isValidDomain(domain) {
		return nil, ErrDomainInvalid
	}
	if reg == "" {
		return nil, ErrInvalidRegion
	}

	token, err := generateChallengeToken()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	return &BYODomain{
		ID:             uuid.New(),
		Domain:         normalizeDomain(domain),
		UserID:         userID,
		ChallengeToken: token,
		State:          BYODomainStatePending,
		Region:         reg,
		CreatedAt:      now,
		ExpiresAt:      now.Add(challengeValidityDuration),
	}, nil
}

// generateChallengeToken creates a cryptographically random challenge token.
func generateChallengeToken() (string, error) {
	b := make([]byte, challengeTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", ErrChallengeGenFailed
	}
	// Defense-in-depth: reject all-zero output (catastrophic RNG failure).
	allZero := true
	for _, v := range b {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "", ErrChallengeGenFailed
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// VerifyTXTChallenge checks that the user has published the correct TXT record
// for domain ownership verification.
// Expected record: _harbor-verify.<domain> IN TXT "harbor-verify=<token>"
func (v *DomainVerifier) VerifyTXTChallenge(ctx context.Context, domain *BYODomain) error {
	if domain.State != BYODomainStatePending {
		return ErrChallengeNotFound
	}
	if time.Now().UTC().After(domain.ExpiresAt) {
		return ErrChallengeExpired
	}

	// Look up the TXT record at _harbor-verify.<domain>
	txtHost := fmt.Sprintf("%s.%s", txtRecordPrefix, domain.Domain)
	records, err := v.resolver.LookupTXT(ctx, txtHost)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return ErrTXTRecordNotFound
		}
		return fmt.Errorf("%w: %w", ErrDNSLookupFailed, err)
	}

	// Look for the expected value: harbor-verify=<token>
	expectedValue := txtValuePrefix + domain.ChallengeToken
	for _, record := range records {
		if strings.TrimSpace(record) == expectedValue {
			// Verification successful
			now := time.Now().UTC()
			domain.State = BYODomainStateVerified
			domain.VerifiedAt = &now
			return nil
		}
	}

	return ErrTXTRecordMismatch
}

// ValidateDNSSetup checks that MX, SPF, and DKIM records are correctly configured
// for the BYO-domain to receive mail through Harbor's relay infrastructure.
func (v *DomainVerifier) ValidateDNSSetup(ctx context.Context, domain string) (*DNSSetupStatus, error) {
	domain = normalizeDomain(domain)
	status := &DNSSetupStatus{}

	// 1. Validate MX records — should point to Harbor's regional MTA
	mxValid, mxRecords, err := v.validateMX(ctx, domain)
	if err != nil && !errors.Is(err, ErrMXRecordNotFound) && !errors.Is(err, ErrMXRecordInvalid) {
		return nil, err
	}
	status.MXValid = mxValid
	status.MXRecords = mxRecords

	// 2. Validate SPF record — should include Harbor's relay domain
	spfValid, spfRecord, err := v.validateSPF(ctx, domain)
	if err != nil && !errors.Is(err, ErrSPFRecordNotFound) && !errors.Is(err, ErrSPFRecordInvalid) {
		return nil, err
	}
	status.SPFValid = spfValid
	status.SPFRecord = spfRecord

	// 3. Validate DKIM record — CNAME to Harbor's DKIM key
	dkimValid, dkimRecord, err := v.validateDKIM(ctx, domain)
	if err != nil && !errors.Is(err, ErrDKIMRecordNotFound) && !errors.Is(err, ErrDKIMRecordInvalid) {
		return nil, err
	}
	status.DKIMValid = dkimValid
	status.DKIMRecord = dkimRecord

	status.AllValid = status.MXValid && status.SPFValid && status.DKIMValid
	return status, nil
}

// validateMX checks that the domain's MX records point to Harbor's regional MTA.
func (v *DomainVerifier) validateMX(ctx context.Context, domain string) (bool, []string, error) {
	mxRecords, err := v.resolver.LookupMX(ctx, domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, nil, ErrMXRecordNotFound
		}
		return false, nil, fmt.Errorf("%w: %w", ErrDNSLookupFailed, err)
	}

	if len(mxRecords) == 0 {
		return false, nil, ErrMXRecordNotFound
	}

	var recordStrings []string
	valid := false
	for _, mx := range mxRecords {
		host := strings.ToLower(strings.TrimSuffix(mx.Host, "."))
		recordStrings = append(recordStrings, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
		// Check if MX points to Harbor's MTA
		if host == v.mtaDomain || strings.HasSuffix(host, "."+v.mtaDomain) {
			valid = true
		}
	}

	if !valid {
		return false, recordStrings, ErrMXRecordInvalid
	}
	return true, recordStrings, nil
}

// validateSPF checks that the domain's SPF record includes Harbor's relay domain.
// Expected: v=spf1 include:relay.<region>.harbor.id ~all
func (v *DomainVerifier) validateSPF(ctx context.Context, domain string) (bool, string, error) {
	txtRecords, err := v.resolver.LookupTXT(ctx, domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, "", ErrSPFRecordNotFound
		}
		return false, "", fmt.Errorf("%w: %w", ErrDNSLookupFailed, err)
	}

	// Find the SPF record (starts with "v=spf1")
	var spfRecord string
	for _, txt := range txtRecords {
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			spfRecord = txt
			break
		}
	}

	if spfRecord == "" {
		return false, "", ErrSPFRecordNotFound
	}

	// Check if SPF includes Harbor's relay domain
	spfLower := strings.ToLower(spfRecord)
	includePattern := "include:" + v.relayDomain
	if strings.Contains(spfLower, includePattern) {
		return true, spfRecord, nil
	}

	return false, spfRecord, ErrSPFRecordInvalid
}

// validateDKIM checks that the DKIM record is correctly configured.
// Expected: harbor._domainkey.<domain> CNAME harbor._domainkey.relay.<region>.harbor.id
func (v *DomainVerifier) validateDKIM(ctx context.Context, domain string) (bool, string, error) {
	dkimHost := fmt.Sprintf("harbor._domainkey.%s", domain)

	// First try CNAME lookup (preferred setup)
	cname, err := v.resolver.LookupCNAME(ctx, dkimHost)
	if err == nil {
		cname = strings.ToLower(strings.TrimSuffix(cname, "."))
		expectedCNAME := fmt.Sprintf("harbor._domainkey.%s", v.relayDomain)
		if cname == expectedCNAME {
			return true, "CNAME " + cname, nil
		}
		return false, "CNAME " + cname, ErrDKIMRecordInvalid
	}

	// Fall back to TXT lookup (direct key publication)
	txtRecords, err := v.resolver.LookupTXT(ctx, dkimHost)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, "", ErrDKIMRecordNotFound
		}
		return false, "", fmt.Errorf("%w: %w", ErrDNSLookupFailed, err)
	}

	// Check for a valid DKIM key record (v=DKIM1; k=rsa; p=...)
	for _, txt := range txtRecords {
		txtLower := strings.ToLower(txt)
		if strings.Contains(txtLower, "v=dkim1") && strings.Contains(txtLower, "p=") {
			return true, txt, nil
		}
	}

	return false, "", ErrDKIMRecordInvalid
}

// ActivateDomain transitions a verified domain to active state after DNS setup
// validation passes. The domain is then ready to receive mail.
func (d *BYODomain) ActivateDomain() error {
	if d.State != BYODomainStateVerified {
		return fmt.Errorf("relay: cannot activate domain in state %s", d.State)
	}
	d.State = BYODomainStateActive
	return nil
}

// MarkFailed transitions the domain to failed state.
func (d *BYODomain) MarkFailed() {
	d.State = BYODomainStateFailed
}

// IsActive returns true if the domain is fully verified and active.
func (d *BYODomain) IsActive() bool {
	return d.State == BYODomainStateActive
}

// IsPending returns true if the domain is awaiting TXT verification.
func (d *BYODomain) IsPending() bool {
	return d.State == BYODomainStatePending
}

// IsVerified returns true if the TXT challenge was verified but DNS setup
// may not be complete.
func (d *BYODomain) IsVerified() bool {
	return d.State == BYODomainStateVerified
}

// GetTXTRecordInstructions returns the DNS record the user needs to create
// for TXT challenge verification.
func (d *BYODomain) GetTXTRecordInstructions() string {
	return fmt.Sprintf("%s.%s IN TXT \"%s%s\"",
		txtRecordPrefix, d.Domain, txtValuePrefix, d.ChallengeToken)
}

// GetMXRecordInstructions returns the DNS record the user needs to create
// for MX setup. The mtaDomain parameter is the regional MTA (e.g., "mta-eu.harbor.id").
func GetMXRecordInstructions(domain, mtaDomain string) string {
	return fmt.Sprintf("%s IN MX 10 %s.", domain, mtaDomain)
}

// GetSPFRecordInstructions returns the DNS record the user needs to create
// for SPF setup. The relayDomain parameter is the regional relay domain.
func GetSPFRecordInstructions(domain, relayDomain string) string {
	return fmt.Sprintf("%s IN TXT \"v=spf1 include:%s ~all\"", domain, relayDomain)
}

// GetDKIMRecordInstructions returns the DNS record the user needs to create
// for DKIM setup. The relayDomain parameter is the regional relay domain.
func GetDKIMRecordInstructions(domain, relayDomain string) string {
	return fmt.Sprintf("harbor._domainkey.%s IN CNAME harbor._domainkey.%s.", domain, relayDomain)
}

// isValidDomain performs basic domain validation.
func isValidDomain(domain string) bool {
	// Basic validation: non-empty, contains at least one dot, no spaces
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return false
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	if strings.ContainsAny(domain, " \t\n\r") {
		return false
	}
	// No leading/trailing dots
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	// Each label must be valid
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" {
			return false
		}
		if len(label) > 63 {
			return false
		}
		// Labels cannot start or end with hyphens
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

// normalizeDomain converts a domain to lowercase and trims whitespace.
func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSpace(domain))
}

// ParseBYODomainState validates and returns a BYODomainState from a string.
func ParseBYODomainState(s string) (BYODomainState, error) {
	switch BYODomainState(s) {
	case BYODomainStatePending, BYODomainStateVerified, BYODomainStateActive, BYODomainStateFailed:
		return BYODomainState(s), nil
	default:
		return "", errors.New("relay: invalid BYO domain state")
	}
}
