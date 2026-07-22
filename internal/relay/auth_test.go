package relay

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"github.com/mileusna/spf"
)

// buildLookupTXT returns a DNS TXT lookup function backed by a static map.
// Keys are normalized to lowercase without trailing dots.
func buildLookupTXT(records map[string][]string) func(string) ([]string, error) {
	return func(domain string) ([]string, error) {
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		if recs, ok := records[domain]; ok {
			return recs, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
	}
}

// stubSPF returns a spfChecker that always returns the given result.
func stubSPF(result spf.Result) spfChecker {
	return func(_ net.IP, _, _, _ string) spf.Result {
		return result
	}
}

// signMessage DKIM-signs a raw RFC 5322 message using the provided key and
// selector/domain, returning the signed message bytes.
func signMessage(t *testing.T, msg []byte, key *rsa.PrivateKey, domain, selector string) []byte {
	t.Helper()
	var buf bytes.Buffer
	opts := &dkim.SignOptions{
		Domain:                 domain,
		Selector:               selector,
		Signer:                 key,
		Hash:                   crypto.SHA256,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
	}
	if err := dkim.Sign(&buf, bytes.NewReader(msg), opts); err != nil {
		t.Fatalf("dkim.Sign failed: %v", err)
	}
	return buf.Bytes()
}

// dkimPublicKeyRecord formats an RSA public key as a DKIM TXT record value.
func dkimPublicKeyRecord(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}

// TestAuthenticate_DKIMPass_SPFPass_DMARCPass verifies a fully authenticated
// message with aligned SPF and valid DKIM signature.
func TestAuthenticate_DKIMPass_SPFPass_DMARCPass(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	rawMsg := "From: Alice <alice@example.com>\r\n" +
		"To: bob@relay.eu.harbor.id\r\n" +
		"Subject: Hello\r\n" +
		"\r\n" +
		"This is the body.\r\n"
	signed := signMessage(t, []byte(rawMsg), key, "example.com", "test")

	lookup := buildLookupTXT(map[string][]string{
		"test._domainkey.example.com": {dkimPublicKeyRecord(t, &key.PublicKey)},
		"_dmarc.example.com":          {"v=DMARC1; p=reject"},
	})

	auth := newAuthenticatorWithResolvers(stubSPF(spf.Pass), lookup)
	res, err := auth.Authenticate(context.Background(), AuthInput{
		RemoteIP: net.ParseIP("192.0.2.1"),
		MailFrom: "bounce@example.com",
		Helo:     "mail.example.com",
		Message:  signed,
	})
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}

	if res.SPF != AuthPass {
		t.Errorf("SPF = %s, want pass", res.SPF)
	}
	if res.DKIM != AuthPass {
		t.Errorf("DKIM = %s, want pass", res.DKIM)
	}
	if res.DMARC != AuthPass {
		t.Errorf("DMARC = %s, want pass", res.DMARC)
	}
	if res.ShouldReject() {
		t.Error("ShouldReject() = true, want false")
	}
}

// TestAuthenticate_DKIMFail_SPFFail_DMARCReject verifies that a message with
// tampered DKIM and failing SPF is rejected when DMARC policy is p=reject.
func TestAuthenticate_DKIMFail_SPFFail_DMARCReject(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	rawMsg := "From: Alice <alice@example.com>\r\n" +
		"To: bob@relay.eu.harbor.id\r\n" +
		"Subject: Hello\r\n" +
		"\r\n" +
		"This is the body.\r\n"
	signed := signMessage(t, []byte(rawMsg), key, "example.com", "test")

	// Tamper with the body to invalidate the signature
	tampered := bytes.Replace(signed, []byte("This is the body."), []byte("TAMPERED BODY!!!"), 1)

	lookup := buildLookupTXT(map[string][]string{
		"test._domainkey.example.com": {dkimPublicKeyRecord(t, &key.PublicKey)},
		"_dmarc.example.com":          {"v=DMARC1; p=reject"},
	})

	auth := newAuthenticatorWithResolvers(stubSPF(spf.Fail), lookup)
	res, err := auth.Authenticate(context.Background(), AuthInput{
		RemoteIP: net.ParseIP("192.0.2.1"),
		MailFrom: "bounce@example.com",
		Helo:     "mail.example.com",
		Message:  tampered,
	})
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}

	if res.SPF != AuthFail {
		t.Errorf("SPF = %s, want fail", res.SPF)
	}
	if res.DKIM != AuthFail {
		t.Errorf("DKIM = %s, want fail", res.DKIM)
	}
	if res.DMARC != AuthFail {
		t.Errorf("DMARC = %s, want fail", res.DMARC)
	}
	if !res.ShouldReject() {
		t.Error("ShouldReject() = false, want true (DMARC p=reject)")
	}
}

// TestAuthenticate_SPFPassUnaligned_NoDKIM_DMARCReject verifies that SPF pass
// with domain misalignment still fails DMARC when there's no valid DKIM.
func TestAuthenticate_SPFPassUnaligned_NoDKIM_DMARCReject(t *testing.T) {
	// Message From: example.com, but MailFrom (SPF domain) is evil.com
	rawMsg := "From: Alice <alice@example.com>\r\n" +
		"To: bob@relay.eu.harbor.id\r\n" +
		"Subject: Hello\r\n" +
		"\r\n" +
		"Body.\r\n"

	lookup := buildLookupTXT(map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=reject"},
	})

	auth := newAuthenticatorWithResolvers(stubSPF(spf.Pass), lookup)
	res, err := auth.Authenticate(context.Background(), AuthInput{
		RemoteIP: net.ParseIP("192.0.2.1"),
		MailFrom: "bounce@evil.com", // Unaligned with From: example.com
		Helo:     "mail.evil.com",
		Message:  []byte(rawMsg),
	})
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}

	if res.SPF != AuthPass {
		t.Errorf("SPF = %s, want pass", res.SPF)
	}
	if res.SPFDomain != "evil.com" {
		t.Errorf("SPFDomain = %s, want evil.com", res.SPFDomain)
	}
	if res.DKIM != AuthNone {
		t.Errorf("DKIM = %s, want none (no signature)", res.DKIM)
	}
	// DMARC should fail: SPF passed but is not aligned (evil.com != example.com)
	if res.DMARC != AuthFail {
		t.Errorf("DMARC = %s, want fail (SPF not aligned)", res.DMARC)
	}
	if !res.ShouldReject() {
		t.Error("ShouldReject() = false, want true")
	}
}

// TestAuthenticate_NoDMARC_SPFPass_Accept verifies that without a DMARC record,
// a passing SPF result causes acceptance.
func TestAuthenticate_NoDMARC_SPFPass_Accept(t *testing.T) {
	rawMsg := "From: Alice <alice@example.com>\r\n" +
		"To: bob@relay.eu.harbor.id\r\n" +
		"Subject: Hello\r\n" +
		"\r\n" +
		"Body.\r\n"

	// No DMARC record
	lookup := buildLookupTXT(map[string][]string{})

	auth := newAuthenticatorWithResolvers(stubSPF(spf.Pass), lookup)
	res, err := auth.Authenticate(context.Background(), AuthInput{
		RemoteIP: net.ParseIP("192.0.2.1"),
		MailFrom: "bounce@example.com",
		Helo:     "mail.example.com",
		Message:  []byte(rawMsg),
	})
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}

	if res.SPF != AuthPass {
		t.Errorf("SPF = %s, want pass", res.SPF)
	}
	if res.DMARC != AuthNone {
		t.Errorf("DMARC = %s, want none (no record)", res.DMARC)
	}
	if res.ShouldReject() {
		t.Error("ShouldReject() = true, want false (SPF pass, no DMARC)")
	}
}

// TestAuthenticate_NoDMARC_SPFFail_Reject verifies that without a DMARC record,
// a failing SPF with no DKIM pass causes rejection.
func TestAuthenticate_NoDMARC_SPFFail_Reject(t *testing.T) {
	rawMsg := "From: Alice <alice@example.com>\r\n" +
		"To: bob@relay.eu.harbor.id\r\n" +
		"Subject: Hello\r\n" +
		"\r\n" +
		"Body.\r\n"

	lookup := buildLookupTXT(map[string][]string{})

	auth := newAuthenticatorWithResolvers(stubSPF(spf.Fail), lookup)
	res, err := auth.Authenticate(context.Background(), AuthInput{
		RemoteIP: net.ParseIP("192.0.2.1"),
		MailFrom: "bounce@example.com",
		Helo:     "mail.example.com",
		Message:  []byte(rawMsg),
	})
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}

	if res.SPF != AuthFail {
		t.Errorf("SPF = %s, want fail", res.SPF)
	}
	if res.DKIM != AuthNone {
		t.Errorf("DKIM = %s, want none", res.DKIM)
	}
	if res.DMARC != AuthNone {
		t.Errorf("DMARC = %s, want none", res.DMARC)
	}
	if !res.ShouldReject() {
		t.Error("ShouldReject() = false, want true (SPF fail, no DKIM pass)")
	}
}

// TestAuthenticate_DMARCQuarantine_NoReject verifies that DMARC p=quarantine
// does not cause rejection (relay has no spam folder).
func TestAuthenticate_DMARCQuarantine_NoReject(t *testing.T) {
	rawMsg := "From: Alice <alice@example.com>\r\n" +
		"To: bob@relay.eu.harbor.id\r\n" +
		"Subject: Hello\r\n" +
		"\r\n" +
		"Body.\r\n"

	lookup := buildLookupTXT(map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=quarantine"},
	})

	auth := newAuthenticatorWithResolvers(stubSPF(spf.Fail), lookup)
	res, err := auth.Authenticate(context.Background(), AuthInput{
		RemoteIP: net.ParseIP("192.0.2.1"),
		MailFrom: "bounce@evil.com",
		Helo:     "mail.evil.com",
		Message:  []byte(rawMsg),
	})
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}

	if res.DMARC != AuthFail {
		t.Errorf("DMARC = %s, want fail", res.DMARC)
	}
	if res.DMARCPolicy != dmarc.PolicyQuarantine {
		t.Errorf("DMARCPolicy = %s, want quarantine", res.DMARCPolicy)
	}
	// Even though DMARC fails, p=quarantine should not cause rejection
	if res.ShouldReject() {
		t.Error("ShouldReject() = true, want false (p=quarantine)")
	}
}

// TestExtractFromDomain tests extraction of the From header domain.
func TestExtractFromDomain(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want string
	}{
		{
			name: "simple address",
			msg:  "From: alice@example.com\r\n\r\n",
			want: "example.com",
		},
		{
			name: "display name",
			msg:  "From: Alice <alice@example.com>\r\n\r\n",
			want: "example.com",
		},
		{
			name: "uppercase domain",
			msg:  "From: alice@EXAMPLE.COM\r\n\r\n",
			want: "example.com",
		},
		{
			name: "missing From",
			msg:  "To: bob@example.com\r\n\r\n",
			want: "",
		},
		{
			name: "malformed From",
			msg:  "From: not-an-email\r\n\r\n",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFromDomain([]byte(tt.msg))
			if got != tt.want {
				t.Errorf("extractFromDomain() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestDomainFromAddress tests domain extraction from various address formats.
func TestDomainFromAddress(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"alice@example.com", "example.com"},
		{"<alice@example.com>", "example.com"},
		{"  alice@EXAMPLE.COM  ", "example.com"},
		{"<>", ""},
		{"", ""},
		{"alice", ""},
		{"@example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got := domainFromAddress(tt.addr)
			if got != tt.want {
				t.Errorf("domainFromAddress(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

// TestDomainsAligned tests DMARC domain alignment checks.
func TestDomainsAligned(t *testing.T) {
	tests := []struct {
		name   string
		d1, d2 string
		mode   dmarc.AlignmentMode
		want   bool
	}{
		{"exact match strict", "example.com", "example.com", dmarc.AlignmentStrict, true},
		{"exact match relaxed", "example.com", "example.com", dmarc.AlignmentRelaxed, true},
		{"subdomain strict", "mail.example.com", "example.com", dmarc.AlignmentStrict, false},
		{"subdomain relaxed", "mail.example.com", "example.com", dmarc.AlignmentRelaxed, true},
		{"different domains relaxed", "example.com", "other.com", dmarc.AlignmentRelaxed, false},
		{"trailing dot", "example.com.", "example.com", dmarc.AlignmentStrict, true},
		{"empty first", "", "example.com", dmarc.AlignmentRelaxed, false},
		{"empty second", "example.com", "", dmarc.AlignmentRelaxed, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := domainsAligned(tt.d1, tt.d2, tt.mode)
			if got != tt.want {
				t.Errorf("domainsAligned(%q, %q, %v) = %v, want %v",
					tt.d1, tt.d2, tt.mode, got, tt.want)
			}
		})
	}
}

// TestOrganizationalDomain tests eTLD+1 extraction.
func TestOrganizationalDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"example.com", "example.com"},
		{"mail.example.com", "example.com"},
		{"deep.sub.example.com", "example.com"},
		{"example.co.uk", "example.co.uk"},
		{"mail.example.co.uk", "example.co.uk"},
		{"", ""},
		{"localhost", "localhost"}, // fallback to input
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := organizationalDomain(tt.domain)
			if got != tt.want {
				t.Errorf("organizationalDomain(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

// TestShouldReject tests the rejection decision logic.
func TestShouldReject(t *testing.T) {
	tests := []struct {
		name           string
		spf            AuthResultValue
		dkim           AuthResultValue
		dmarc          AuthResultValue
		dmarcPolicy    dmarc.Policy
		hasDMARCRecord bool
		want           bool
	}{
		// With DMARC record
		{"DMARC pass, p=reject", AuthPass, AuthPass, AuthPass, dmarc.PolicyReject, true, false},
		{"DMARC fail, p=reject", AuthFail, AuthFail, AuthFail, dmarc.PolicyReject, true, true},
		{"DMARC fail, p=quarantine", AuthFail, AuthFail, AuthFail, dmarc.PolicyQuarantine, true, false},
		{"DMARC fail, p=none", AuthFail, AuthFail, AuthFail, dmarc.PolicyNone, true, false},

		// Without DMARC record (fallback logic)
		{"no DMARC, SPF pass", AuthPass, AuthNone, AuthNone, "", false, false},
		{"no DMARC, DKIM pass", AuthNone, AuthPass, AuthNone, "", false, false},
		{"no DMARC, SPF fail, DKIM none", AuthFail, AuthNone, AuthNone, "", false, true},
		{"no DMARC, SPF softfail, DKIM none", AuthSoftfail, AuthNone, AuthNone, "", false, true},
		{"no DMARC, SPF none, DKIM fail", AuthNone, AuthFail, AuthNone, "", false, true},
		{"no DMARC, all none", AuthNone, AuthNone, AuthNone, "", false, false},
		{"no DMARC, SPF neutral", AuthNeutral, AuthNone, AuthNone, "", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &AuthResult{
				SPF:            tt.spf,
				DKIM:           tt.dkim,
				DMARC:          tt.dmarc,
				DMARCPolicy:    tt.dmarcPolicy,
				hasDMARCRecord: tt.hasDMARCRecord,
			}
			got := r.ShouldReject()
			if got != tt.want {
				t.Errorf("ShouldReject() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMapSPFResult tests conversion from spf.Result to AuthResultValue.
func TestMapSPFResult(t *testing.T) {
	tests := []struct {
		in   spf.Result
		want AuthResultValue
	}{
		{spf.Pass, AuthPass},
		{spf.Fail, AuthFail},
		{spf.Softfail, AuthSoftfail},
		{spf.Neutral, AuthNeutral},
		{spf.TempError, AuthTempError},
		{spf.PermError, AuthPermError},
		{spf.None, AuthNone},
	}

	for _, tt := range tests {
		t.Run(string(tt.in), func(t *testing.T) {
			got := mapSPFResult(tt.in)
			if got != tt.want {
				t.Errorf("mapSPFResult(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestAggregateDKIM tests collapsing multiple DKIM results.
func TestAggregateDKIM(t *testing.T) {
	tests := []struct {
		name string
		sigs []DKIMVerification
		want AuthResultValue
	}{
		{"empty", nil, AuthNone},
		{"single pass", []DKIMVerification{{Result: AuthPass}}, AuthPass},
		{"single fail", []DKIMVerification{{Result: AuthFail}}, AuthFail},
		{"pass and fail", []DKIMVerification{{Result: AuthFail}, {Result: AuthPass}}, AuthPass},
		{"temp and fail", []DKIMVerification{{Result: AuthTempError}, {Result: AuthFail}}, AuthFail},
		{"temp only", []DKIMVerification{{Result: AuthTempError}}, AuthTempError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := aggregateDKIM(tt.sigs)
			if got != tt.want {
				t.Errorf("aggregateDKIM() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNewAuthenticator verifies the public constructor.
func TestNewAuthenticator(t *testing.T) {
	auth := NewAuthenticator()
	if auth == nil {
		t.Fatal("NewAuthenticator() returned nil")
	}
	if auth.spfCheck == nil {
		t.Error("spfCheck is nil")
	}
	// lookupTXT should be nil (use system resolver)
	if auth.lookupTXT != nil {
		t.Error("lookupTXT should be nil for live DNS")
	}
}
