package relay

import (
	"bytes"
	"context"
	"net"
	"net/mail"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"github.com/mileusna/spf"
	"golang.org/x/net/publicsuffix"
)

// AuthResultValue is the outcome of an individual authentication mechanism
// (SPF, DKIM, or DMARC), mirroring the vocabulary of RFC 7601.
type AuthResultValue string

const (
	// AuthNone means the mechanism did not apply (no record / no signature).
	AuthNone AuthResultValue = "none"
	// AuthPass means the mechanism verified successfully.
	AuthPass AuthResultValue = "pass"
	// AuthFail means the mechanism explicitly failed.
	AuthFail AuthResultValue = "fail"
	// AuthSoftfail means SPF returned a soft failure (~all).
	AuthSoftfail AuthResultValue = "softfail"
	// AuthNeutral means the mechanism made no assertion.
	AuthNeutral AuthResultValue = "neutral"
	// AuthTempError means a transient error occurred (e.g., DNS timeout).
	AuthTempError AuthResultValue = "temperror"
	// AuthPermError means a permanent error occurred (e.g., malformed record).
	AuthPermError AuthResultValue = "permerror"
)

// Note: A missing From header does not return an error; it simply leaves
// DMARC unevaluable while SPF/DKIM continue to run.

// DKIMVerification is the result of verifying a single DKIM signature.
type DKIMVerification struct {
	// Domain is the SDID (signing domain) claimed by the signature.
	Domain string
	// Result is pass if the signature verified, fail otherwise.
	Result AuthResultValue
}

// AuthResult holds the combined outcome of SPF, DKIM, and DMARC evaluation
// for a single inbound message.
type AuthResult struct {
	// SPF is the aggregate SPF result for the envelope sender.
	SPF AuthResultValue
	// SPFDomain is the domain SPF was evaluated against (MAIL FROM domain).
	SPFDomain string

	// DKIM is the best DKIM result across all signatures (pass if any passed).
	DKIM AuthResultValue
	// DKIMSignatures holds the per-signature verification results.
	DKIMSignatures []DKIMVerification

	// DMARC is the DMARC evaluation result (pass/fail/none).
	DMARC AuthResultValue
	// DMARCPolicy is the published policy (p=) when a DMARC record was found.
	DMARCPolicy dmarc.Policy
	// FromDomain is the RFC 5322 From header domain used for DMARC alignment.
	FromDomain string

	// hasDMARCRecord records whether a DMARC policy was published for the domain.
	hasDMARCRecord bool
}

// ShouldReject reports whether the message should be rejected based on the
// authentication outcome.
//
// Policy:
//   - If the sending domain publishes a DMARC record: reject only when DMARC
//     fails AND the published policy is p=reject. Quarantine/none are accepted
//     (delivered) since the relay does not maintain a spam folder.
//   - If no DMARC record exists: fall back to a conservative SPF/DKIM check —
//     accept when either SPF or DKIM passes, reject when either explicitly
//     fails and neither passes, and accept otherwise (no assertion possible).
func (r *AuthResult) ShouldReject() bool {
	if r.hasDMARCRecord {
		return r.DMARC == AuthFail && r.DMARCPolicy == dmarc.PolicyReject
	}

	if r.SPF == AuthPass || r.DKIM == AuthPass {
		return false
	}
	if r.SPF == AuthFail || r.SPF == AuthSoftfail || r.DKIM == AuthFail {
		return true
	}
	return false
}

// AuthInput carries the data needed to authenticate an inbound message.
type AuthInput struct {
	// RemoteIP is the IP address of the connecting SMTP client (for SPF).
	RemoteIP net.IP
	// MailFrom is the envelope sender (MAIL FROM), used for SPF and DMARC
	// SPF-alignment.
	MailFrom string
	// Helo is the HELO/EHLO hostname, used as an SPF fallback for null senders.
	Helo string
	// Message is the raw RFC 5322 message (headers + body). It is used for DKIM
	// verification and to extract the From header domain. It is processed in
	// memory only and never persisted (§7.5.6).
	Message []byte
}

// spfChecker is the function signature used to perform SPF checks. It matches
// spf.CheckHost and is injectable for deterministic testing.
type spfChecker func(ip net.IP, domain, sender, helo string) spf.Result

// Authenticator verifies SPF, DKIM signatures, and DMARC alignment for inbound
// relay messages.
type Authenticator struct {
	// spfCheck performs the SPF evaluation (defaults to spf.CheckHost).
	spfCheck spfChecker
	// lookupTXT resolves DNS TXT records for DKIM and DMARC. When nil, the
	// underlying libraries use net.LookupTXT.
	lookupTXT func(domain string) ([]string, error)
}

// NewAuthenticator returns an Authenticator that uses live DNS resolution.
func NewAuthenticator() *Authenticator {
	return &Authenticator{
		spfCheck:  spf.CheckHost,
		lookupTXT: nil,
	}
}

// newAuthenticatorWithResolvers builds an Authenticator with injectable SPF and
// TXT resolution, used for deterministic testing.
func newAuthenticatorWithResolvers(spfCheck spfChecker, lookupTXT func(string) ([]string, error)) *Authenticator {
	if spfCheck == nil {
		spfCheck = spf.CheckHost
	}
	return &Authenticator{
		spfCheck:  spfCheck,
		lookupTXT: lookupTXT,
	}
}

// Authenticate evaluates SPF, DKIM, and DMARC for the given message and returns
// a combined AuthResult. It does not itself reject mail — callers should use
// AuthResult.ShouldReject to decide. A non-nil error is only returned for
// unexpected internal failures; ordinary authentication failures are reported
// via the result values.
func (a *Authenticator) Authenticate(_ context.Context, in AuthInput) (*AuthResult, error) {
	res := &AuthResult{
		SPF:   AuthNone,
		DKIM:  AuthNone,
		DMARC: AuthNone,
	}

	// Extract the RFC 5322 From domain (used for DMARC alignment). A missing or
	// malformed From header leaves DMARC unevaluable; SPF/DKIM still run.
	fromDomain := extractFromDomain(in.Message)
	res.FromDomain = fromDomain

	// Determine the domain SPF/DMARC-SPF should authenticate against. Prefer the
	// MAIL FROM domain; fall back to HELO for null senders (bounces).
	mailFromDomain := domainFromAddress(in.MailFrom)
	if mailFromDomain == "" {
		mailFromDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Helo), "."))
	}

	// 1. SPF — authorize the connecting IP for the envelope-sender domain.
	if in.RemoteIP != nil && mailFromDomain != "" {
		res.SPF = mapSPFResult(a.spfCheck(in.RemoteIP, mailFromDomain, in.MailFrom, in.Helo))
		res.SPFDomain = mailFromDomain
	}

	// 2. DKIM — verify each signature in the message.
	verifs, err := dkim.VerifyWithOptions(bytes.NewReader(in.Message), &dkim.VerifyOptions{
		LookupTXT: a.lookupTXT,
	})
	if err != nil {
		// A parse-level failure (e.g., malformed message) is a permanent error.
		res.DKIM = AuthPermError
	} else {
		for _, v := range verifs {
			dv := DKIMVerification{Domain: v.Domain, Result: AuthPass}
			if v.Err != nil {
				if dkim.IsTempFail(v.Err) {
					dv.Result = AuthTempError
				} else {
					dv.Result = AuthFail
				}
			}
			res.DKIMSignatures = append(res.DKIMSignatures, dv)
		}
		res.DKIM = aggregateDKIM(res.DKIMSignatures)
	}

	// 3. DMARC — look up the policy and evaluate identifier alignment.
	if fromDomain != "" {
		a.evaluateDMARC(res, fromDomain)
	}

	return res, nil
}

// evaluateDMARC looks up the DMARC record for fromDomain (falling back to the
// organizational domain) and sets the DMARC result on res based on SPF/DKIM
// identifier alignment.
func (a *Authenticator) evaluateDMARC(res *AuthResult, fromDomain string) {
	record := a.dmarcLookup(fromDomain)
	if record == nil {
		// Try the organizational domain (RFC 7489 §6.6.3).
		if org := organizationalDomain(fromDomain); org != "" && org != fromDomain {
			record = a.dmarcLookup(org)
		}
	}
	if record == nil {
		res.DMARC = AuthNone
		return
	}

	res.hasDMARCRecord = true
	res.DMARCPolicy = record.Policy

	spfAligned := res.SPF == AuthPass &&
		domainsAligned(res.SPFDomain, fromDomain, record.SPFAlignment)

	dkimAligned := false
	for _, dv := range res.DKIMSignatures {
		if dv.Result == AuthPass && domainsAligned(dv.Domain, fromDomain, record.DKIMAlignment) {
			dkimAligned = true
			break
		}
	}

	if spfAligned || dkimAligned {
		res.DMARC = AuthPass
	} else {
		res.DMARC = AuthFail
	}
}

// dmarcLookup resolves the DMARC record for a domain, returning nil when no
// policy is published or the lookup fails.
func (a *Authenticator) dmarcLookup(domain string) *dmarc.Record {
	var (
		record *dmarc.Record
		err    error
	)
	if a.lookupTXT != nil {
		record, err = dmarc.LookupWithOptions(domain, &dmarc.LookupOptions{LookupTXT: a.lookupTXT})
	} else {
		record, err = dmarc.Lookup(domain)
	}
	if err != nil {
		return nil
	}
	return record
}

// aggregateDKIM collapses per-signature results into a single value: pass if any
// signature passed, fail if any failed, temperror if any had transient failures,
// or none when there are no signatures.
func aggregateDKIM(sigs []DKIMVerification) AuthResultValue {
	if len(sigs) == 0 {
		return AuthNone
	}
	var sawFail, sawTemp bool
	for _, s := range sigs {
		switch s.Result {
		case AuthPass:
			return AuthPass
		case AuthTempError:
			sawTemp = true
		case AuthFail:
			sawFail = true
		}
	}
	if sawFail {
		return AuthFail
	}
	if sawTemp {
		return AuthTempError
	}
	return AuthFail
}

// mapSPFResult converts a mileusna/spf result into an AuthResultValue.
func mapSPFResult(r spf.Result) AuthResultValue {
	switch r {
	case spf.Pass:
		return AuthPass
	case spf.Fail:
		return AuthFail
	case spf.Softfail:
		return AuthSoftfail
	case spf.Neutral:
		return AuthNeutral
	case spf.TempError:
		return AuthTempError
	case spf.PermError:
		return AuthPermError
	default:
		return AuthNone
	}
}

// extractFromDomain parses the RFC 5322 From header and returns the (lowercased)
// domain of the first address, or "" if it cannot be determined.
func extractFromDomain(msg []byte) string {
	m, err := mail.ReadMessage(bytes.NewReader(msg))
	if err != nil {
		return ""
	}
	from := m.Header.Get("From")
	if from == "" {
		return ""
	}
	addrs, err := mail.ParseAddressList(from)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	return domainFromAddress(addrs[0].Address)
}

// domainFromAddress returns the lowercased domain part of an email address,
// tolerating angle brackets and surrounding whitespace. Returns "" when there
// is no local part or no domain (e.g., the SMTP null sender "<>" or "@example.com").
func domainFromAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(addr, "<")
	addr = strings.TrimSuffix(addr, ">")
	at := strings.LastIndex(addr, "@")
	// Require both a local part (at > 0) and a domain (at < len-1)
	if at <= 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}

// domainsAligned reports whether two domains are aligned under the given DMARC
// alignment mode. Strict alignment requires an exact match; relaxed alignment
// (the default) requires the organizational domains to match.
func domainsAligned(d1, d2 string, mode dmarc.AlignmentMode) bool {
	d1 = strings.ToLower(strings.TrimSuffix(d1, "."))
	d2 = strings.ToLower(strings.TrimSuffix(d2, "."))
	if d1 == "" || d2 == "" {
		return false
	}
	if mode == dmarc.AlignmentStrict {
		return d1 == d2
	}
	return organizationalDomain(d1) == organizationalDomain(d2)
}

// organizationalDomain returns the registrable (eTLD+1) domain for a hostname,
// falling back to the input when it cannot be determined.
func organizationalDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return ""
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return domain
	}
	return etld1
}
