package relay

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
)

// ARC (Authenticated Received Chain, RFC 8617) header field names. A single ARC
// "set" is three header fields sharing an instance number i=N:
//   - ARC-Authentication-Results (AAR): the SPF/DKIM/DMARC verdicts we observed.
//   - ARC-Message-Signature (AMS): a DKIM-like signature over headers + body
//     (but never over any ARC-* headers).
//   - ARC-Seal (AS): a signature over the ARC header fields themselves, with a
//     chain-validation tag (cv=). For a first-hop forwarder this is cv=none.
const (
	arcAuthResultsName = "ARC-Authentication-Results"
	arcMsgSigName      = "ARC-Message-Signature"
	arcSealName        = "ARC-Seal"
)

// arcSignedHeaders is the preferred set of headers the ARC-Message-Signature
// covers, in signing order. Only headers actually present in the message are
// included. ARC-* headers are intentionally excluded (RFC 8617 §5.1.1).
var arcSignedHeaders = []string{
	"From", "To", "Cc", "Subject", "Date", "Message-ID",
	"MIME-Version", "Content-Type", "Reply-To",
}

// Forwarder delivers a sealed message to a user's real inbox via outbound SMTP.
// The message reader is consumed once; implementations MUST NOT retain or log
// the message body (§7.5.6).
type Forwarder interface {
	Forward(ctx context.Context, from, to string, msg io.Reader) error
}

// MappingResolver resolves a relay Address (plus its envelope-encrypted mapping)
// to the user's real email address. This is the only point where the opaque
// relay token is linked back to a real person, so implementations keep the
// plaintext email in memory only for the duration of forwarding.
type MappingResolver interface {
	ResolveRealEmail(ctx context.Context, addr *Address, encMapping []byte) (string, error)
}

// SMTPForwarder forwards messages to a configured outbound SMTP smart host.
type SMTPForwarder struct {
	// Addr is the host:port of the outbound SMTP server.
	Addr string
}

// NewSMTPForwarder returns a Forwarder that relays via the given SMTP smart host.
func NewSMTPForwarder(addr string) *SMTPForwarder {
	return &SMTPForwarder{Addr: addr}
}

// Forward delivers the message via outbound SMTP. The body is streamed directly
// to the smart host and never retained or logged.
func (f *SMTPForwarder) Forward(_ context.Context, from, to string, msg io.Reader) error {
	return smtp.SendMail(f.Addr, nil, from, []string{to}, msg)
}

// ARCSealer affixes an ARC set (AAR + AMS + AS) to a message before it is
// forwarded, preserving the original authentication results across the relay
// hop (RFC 8617). This is a first-hop sealer: it always emits instance i=1 with
// cv=none.
type ARCSealer struct {
	domain     string // signing domain (d=)
	selector   string // key selector (s=)
	authservID string // authserv-id used in the AAR
	key        *rsa.PrivateKey
	now        func() time.Time
}

// NewARCSealer creates an ARC sealer for the given signing domain and selector,
// using the provided RSA private key. The DKIM public key for verification must
// be published at <selector>._domainkey.<domain>.
func NewARCSealer(domain, selector string, key *rsa.PrivateKey) *ARCSealer {
	return &ARCSealer{
		domain:     domain,
		selector:   selector,
		authservID: domain,
		key:        key,
		now:        time.Now,
	}
}

// Seal returns a copy of msg with a fresh ARC set prepended. The returned bytes
// are the complete message ready to forward. The input is never modified,
// logged, or persisted.
func (s *ARCSealer) Seal(msg []byte, result *AuthResult) ([]byte, error) {
	if s.key == nil {
		return nil, errors.New("relay: ARC sealer has no signing key")
	}

	// Normalize to CRLF so our signatures match the bytes we forward.
	norm := normalizeCRLF(msg)
	fields, body := splitHeadersBody(norm)

	const instance = 1
	timestamp := s.now().Unix()

	// 1. ARC-Authentication-Results (AAR) — records the verdicts we observed.
	aarValue := fmt.Sprintf(" i=%d; %s", instance, formatAuthResults(s.authservID, result))
	aarHeader := arcAuthResultsName + ":" + aarValue + "\r\n"

	// 2. ARC-Message-Signature (AMS) — DKIM-style signature over headers + body.
	hList := presentSignedHeaders(fields)
	bh := bodyHashRelaxed(body)
	amsValue := fmt.Sprintf(
		" i=%d; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; t=%d; h=%s; bh=%s; b=",
		instance, s.domain, s.selector, timestamp, strings.Join(hList, ":"), bh,
	)

	var amsInput bytes.Buffer
	for _, hName := range hList {
		v, ok := findHeader(fields, hName)
		if !ok {
			continue
		}
		amsInput.WriteString(canonHeaderRelaxed(hName, v))
		amsInput.WriteString("\r\n")
	}
	// The AMS header signs itself with an empty b= value and no trailing CRLF.
	amsInput.WriteString(canonHeaderRelaxed(arcMsgSigName, amsValue))
	amsSig, err := s.sign(amsInput.Bytes())
	if err != nil {
		return nil, fmt.Errorf("relay: sign ARC-Message-Signature: %w", err)
	}
	amsFullValue := amsValue + amsSig
	amsHeader := arcMsgSigName + ":" + amsFullValue + "\r\n"

	// 3. ARC-Seal (AS) — signs the ARC header fields in order (AAR, AMS, AS).
	// It has no body hash and carries the chain-validation tag cv=none (i=1).
	asValue := fmt.Sprintf(
		" i=%d; a=rsa-sha256; cv=none; d=%s; s=%s; t=%d; b=",
		instance, s.domain, s.selector, timestamp,
	)

	var asInput bytes.Buffer
	asInput.WriteString(canonHeaderRelaxed(arcAuthResultsName, aarValue))
	asInput.WriteString("\r\n")
	asInput.WriteString(canonHeaderRelaxed(arcMsgSigName, amsFullValue))
	asInput.WriteString("\r\n")
	// The AS header signs itself with an empty b= value and no trailing CRLF.
	asInput.WriteString(canonHeaderRelaxed(arcSealName, asValue))
	asSig, err := s.sign(asInput.Bytes())
	if err != nil {
		return nil, fmt.Errorf("relay: sign ARC-Seal: %w", err)
	}
	asHeader := arcSealName + ":" + asValue + asSig + "\r\n"

	// Prepend the ARC set (Seal topmost) followed by the original message.
	var out bytes.Buffer
	out.Grow(len(norm) + len(aarHeader) + len(amsHeader) + len(asHeader))
	out.WriteString(asHeader)
	out.WriteString(amsHeader)
	out.WriteString(aarHeader)
	out.Write(norm)
	return out.Bytes(), nil
}

// sign computes an RSA-SHA256 signature over data and returns it base64-encoded.
func (s *ARCSealer) sign(data []byte) (string, error) {
	sum := sha256.Sum256(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// formatAuthResults renders the authentication-results portion of an AAR header
// (without the leading "i=N;"). A nil result yields just the authserv-id.
func formatAuthResults(authservID string, res *AuthResult) string {
	if res == nil {
		return authservID
	}
	parts := []string{authservID}
	if res.SPF != "" {
		p := "spf=" + string(res.SPF)
		if res.SPFDomain != "" {
			p += " smtp.mailfrom=" + res.SPFDomain
		}
		parts = append(parts, p)
	}
	if res.DKIM != "" {
		p := "dkim=" + string(res.DKIM)
		if len(res.DKIMSignatures) > 0 && res.DKIMSignatures[0].Domain != "" {
			p += " header.d=" + res.DKIMSignatures[0].Domain
		}
		parts = append(parts, p)
	}
	if res.DMARC != "" {
		p := "dmarc=" + string(res.DMARC)
		if res.FromDomain != "" {
			p += " header.from=" + res.FromDomain
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; ")
}

// headerField is a single raw RFC 5322 header field: its name and raw value
// (including any folding CRLF+WSP and the trailing CRLF).
type headerField struct {
	name  string
	value string
}

// normalizeCRLF converts all line endings in b to CRLF.
func normalizeCRLF(b []byte) []byte {
	s := bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	s = bytes.ReplaceAll(s, []byte("\r"), []byte("\n"))
	s = bytes.ReplaceAll(s, []byte("\n"), []byte("\r\n"))
	return s
}

// splitHeadersBody splits a CRLF-normalized message into its header fields and
// body. The body is the raw bytes after the header/body separator.
func splitHeadersBody(msg []byte) ([]headerField, []byte) {
	idx := bytes.Index(msg, []byte("\r\n\r\n"))
	if idx < 0 {
		return parseHeaderFields(msg), nil
	}
	// Include the trailing CRLF of the final header line in the header block.
	headerBlock := msg[:idx+2]
	body := msg[idx+4:]
	return parseHeaderFields(headerBlock), body
}

// parseHeaderFields parses a header block into fields, preserving folding.
func parseHeaderFields(block []byte) []headerField {
	var fields []headerField
	rawLines := strings.SplitAfter(string(block), "\r\n")

	var cur strings.Builder
	started := false
	flush := func() {
		if !started {
			return
		}
		field := cur.String()
		cur.Reset()
		started = false
		ci := strings.Index(field, ":")
		if ci < 0 {
			return
		}
		fields = append(fields, headerField{name: field[:ci], value: field[ci+1:]})
	}

	for _, ln := range rawLines {
		if ln == "" || ln == "\r\n" {
			continue
		}
		if started && (ln[0] == ' ' || ln[0] == '\t') {
			cur.WriteString(ln) // folded continuation line
			continue
		}
		flush()
		cur.WriteString(ln)
		started = true
	}
	flush()
	return fields
}

// findHeader returns the raw value of the first header matching name
// (case-insensitive).
func findHeader(fields []headerField, name string) (string, bool) {
	for _, f := range fields {
		if strings.EqualFold(strings.TrimSpace(f.name), name) {
			return f.value, true
		}
	}
	return "", false
}

// presentSignedHeaders returns the arcSignedHeaders present in fields, in order.
func presentSignedHeaders(fields []headerField) []string {
	var out []string
	for _, pref := range arcSignedHeaders {
		if _, ok := findHeader(fields, pref); ok {
			out = append(out, pref)
		}
	}
	return out
}

// canonHeaderRelaxed applies RFC 6376 §3.4.2 relaxed header canonicalization to
// a single header field, returning "name:value" with no trailing CRLF.
func canonHeaderRelaxed(name, value string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	v := strings.ReplaceAll(value, "\r\n", "")
	v = strings.ReplaceAll(v, "\n", "")
	v = collapseWSP(v)
	v = strings.TrimRight(v, " ")
	v = strings.TrimLeft(v, " ")
	return name + ":" + v
}

// canonBodyRelaxed applies RFC 6376 §3.4.4 relaxed body canonicalization.
func canonBodyRelaxed(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}
	lines := strings.Split(string(body), "\r\n")
	for i, ln := range lines {
		lines[i] = strings.TrimRight(collapseWSP(ln), " ")
	}
	joined := strings.TrimRight(strings.Join(lines, "\r\n"), "\r\n")
	if joined == "" {
		return nil
	}
	return []byte(joined + "\r\n")
}

// bodyHashRelaxed returns the base64 SHA-256 hash of the relaxed-canonicalized
// body.
func bodyHashRelaxed(body []byte) string {
	sum := sha256.Sum256(canonBodyRelaxed(body))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// collapseWSP replaces every run of spaces/tabs with a single space.
func collapseWSP(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inWSP := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' {
			if !inWSP {
				b.WriteByte(' ')
				inWSP = true
			}
			continue
		}
		b.WriteByte(c)
		inWSP = false
	}
	return b.String()
}

// parseTagList parses a DKIM/ARC tag list ("k=v; k2=v2") into a map. Values are
// trimmed of surrounding whitespace. Used by tests to extract signature values.
func parseTagList(s string) map[string]string {
	m := make(map[string]string)
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.Index(part, "=")
		if eq < 0 {
			continue
		}
		m[strings.TrimSpace(part[:eq])] = strings.TrimSpace(part[eq+1:])
	}
	return m
}
