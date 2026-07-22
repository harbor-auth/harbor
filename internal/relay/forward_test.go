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
	"io"
	"strings"
	"testing"
	"time"
)

// TestARCSealer_Seal verifies that the ARC sealer produces a valid ARC set with
// all three headers (ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results).
func TestARCSealer_Seal(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	sealer := NewARCSealer("relay.example.com", "arc", key)
	// Fix timestamp for deterministic tests
	sealer.now = func() time.Time { return time.Unix(1700000000, 0) }

	msg := "From: alice@example.com\r\n" +
		"To: bob@example.org\r\n" +
		"Subject: Test\r\n" +
		"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
		"Message-ID: <test@example.com>\r\n" +
		"\r\n" +
		"Hello, World!\r\n"

	result := &AuthResult{
		SPF:       AuthPass,
		SPFDomain: "example.com",
		DKIM:      AuthPass,
		DKIMSignatures: []DKIMVerification{
			{Domain: "example.com", Result: AuthPass},
		},
		DMARC:      AuthPass,
		FromDomain: "example.com",
	}

	sealed, err := sealer.Seal([]byte(msg), result)
	if err != nil {
		t.Fatalf("Seal() error: %v", err)
	}

	sealedStr := string(sealed)

	// Verify ARC-Seal is present and first
	if !strings.HasPrefix(sealedStr, "ARC-Seal:") {
		t.Error("sealed message should start with ARC-Seal")
	}

	// Verify all three ARC headers are present
	if !strings.Contains(sealedStr, "ARC-Seal:") {
		t.Error("missing ARC-Seal header")
	}
	if !strings.Contains(sealedStr, "ARC-Message-Signature:") {
		t.Error("missing ARC-Message-Signature header")
	}
	if !strings.Contains(sealedStr, "ARC-Authentication-Results:") {
		t.Error("missing ARC-Authentication-Results header")
	}

	// Verify instance number i=1
	if !strings.Contains(sealedStr, "i=1") {
		t.Error("missing instance number i=1")
	}

	// Verify cv=none (first-hop sealer)
	if !strings.Contains(sealedStr, "cv=none") {
		t.Error("missing chain validation cv=none")
	}

	// Verify the original message is preserved at the end
	if !strings.Contains(sealedStr, "Hello, World!") {
		t.Error("original message body not preserved")
	}

	// Verify the AAR contains authentication results
	if !strings.Contains(sealedStr, "spf=pass") {
		t.Error("AAR should contain spf=pass")
	}
	if !strings.Contains(sealedStr, "dkim=pass") {
		t.Error("AAR should contain dkim=pass")
	}
	if !strings.Contains(sealedStr, "dmarc=pass") {
		t.Error("AAR should contain dmarc=pass")
	}
}

// TestARCSealer_Seal_NilResult verifies sealing works with nil auth results.
func TestARCSealer_Seal_NilResult(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	sealer := NewARCSealer("relay.example.com", "arc", key)

	msg := "From: alice@example.com\r\n\r\nBody.\r\n"
	sealed, err := sealer.Seal([]byte(msg), nil)
	if err != nil {
		t.Fatalf("Seal() error: %v", err)
	}

	if !strings.Contains(string(sealed), "ARC-Seal:") {
		t.Error("missing ARC-Seal header")
	}
}

// TestARCSealer_Seal_NoKey verifies that sealing fails without a key.
func TestARCSealer_Seal_NoKey(t *testing.T) {
	sealer := &ARCSealer{
		domain:   "example.com",
		selector: "arc",
		key:      nil,
	}

	msg := "From: alice@example.com\r\n\r\nBody.\r\n"
	_, err := sealer.Seal([]byte(msg), nil)
	if err == nil {
		t.Error("Seal() should fail without a key")
	}
}

// TestARCSealer_Seal_SignatureVerifies verifies that the generated AMS signature
// can be verified by recomputing it.
func TestARCSealer_Seal_SignatureVerifies(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	sealer := NewARCSealer("relay.example.com", "arc", key)
	fixedTime := time.Unix(1700000000, 0)
	sealer.now = func() time.Time { return fixedTime }

	msg := "From: alice@example.com\r\n" +
		"To: bob@example.org\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"Body.\r\n"

	sealed, err := sealer.Seal([]byte(msg), nil)
	if err != nil {
		t.Fatalf("Seal() error: %v", err)
	}

	// Extract the AMS header and verify its signature
	fields, _ := splitHeadersBody(sealed)
	amsValue, ok := findHeader(fields, "ARC-Message-Signature")
	if !ok {
		t.Fatal("ARC-Message-Signature not found")
	}

	// Parse the signature tag
	tags := parseTagList(amsValue)
	bValue, ok := tags["b"]
	if !ok || bValue == "" {
		t.Fatal("AMS b= tag not found or empty")
	}

	// Decode the signature
	sig, err := base64.StdEncoding.DecodeString(bValue)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	// Reconstruct the signing input
	norm := normalizeCRLF([]byte(msg))
	origFields, body := splitHeadersBody(norm)
	hList := presentSignedHeaders(origFields)
	bh := bodyHashRelaxed(body)

	amsValueEmpty := " i=1; a=rsa-sha256; c=relaxed/relaxed; d=relay.example.com; s=arc; t=1700000000; h=" +
		strings.Join(hList, ":") + "; bh=" + bh + "; b="

	var input bytes.Buffer
	for _, hName := range hList {
		v, _ := findHeader(origFields, hName)
		input.WriteString(canonHeaderRelaxed(hName, v))
		input.WriteString("\r\n")
	}
	input.WriteString(canonHeaderRelaxed("ARC-Message-Signature", amsValueEmpty))

	// Verify the signature
	sum := sha256.Sum256(input.Bytes())
	err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig)
	if err != nil {
		t.Errorf("AMS signature verification failed: %v", err)
	}
}

// TestFormatAuthResults tests the authentication results formatting.
func TestFormatAuthResults(t *testing.T) {
	tests := []struct {
		name     string
		result   *AuthResult
		contains []string
	}{
		{
			name:     "nil result",
			result:   nil,
			contains: []string{"authserv.example.com"},
		},
		{
			name: "full results",
			result: &AuthResult{
				SPF:       AuthPass,
				SPFDomain: "example.com",
				DKIM:      AuthFail,
				DKIMSignatures: []DKIMVerification{
					{Domain: "example.com", Result: AuthFail},
				},
				DMARC:      AuthPass,
				FromDomain: "example.com",
			},
			contains: []string{
				"spf=pass",
				"smtp.mailfrom=example.com",
				"dkim=fail",
				"header.d=example.com",
				"dmarc=pass",
				"header.from=example.com",
			},
		},
		{
			name: "spf only",
			result: &AuthResult{
				SPF:       AuthSoftfail,
				SPFDomain: "test.com",
			},
			contains: []string{"spf=softfail", "smtp.mailfrom=test.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatAuthResults("authserv.example.com", tt.result)
			for _, want := range tt.contains {
				if !strings.Contains(got, want) {
					t.Errorf("formatAuthResults() = %q, want to contain %q", got, want)
				}
			}
		})
	}
}

// TestNormalizeCRLF tests line ending normalization.
func TestNormalizeCRLF(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"already CRLF", "a\r\nb\r\n", "a\r\nb\r\n"},
		{"LF only", "a\nb\n", "a\r\nb\r\n"},
		{"CR only", "a\rb\r", "a\r\nb\r\n"},
		{"mixed", "a\r\nb\nc\rd\r\n", "a\r\nb\r\nc\r\nd\r\n"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(normalizeCRLF([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("normalizeCRLF() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSplitHeadersBody tests header/body splitting.
func TestSplitHeadersBody(t *testing.T) {
	msg := "From: alice@example.com\r\n" +
		"To: bob@example.org\r\n" +
		"\r\n" +
		"Body text\r\n"

	fields, body := splitHeadersBody([]byte(msg))

	if len(fields) != 2 {
		t.Errorf("expected 2 header fields, got %d", len(fields))
	}

	if string(body) != "Body text\r\n" {
		t.Errorf("body = %q, want %q", string(body), "Body text\r\n")
	}
}

// TestCanonHeaderRelaxed tests relaxed header canonicalization.
func TestCanonHeaderRelaxed(t *testing.T) {
	tests := []struct {
		name  string
		hName string
		value string
		want  string
	}{
		{
			name:  "simple",
			hName: "From",
			value: " alice@example.com\r\n",
			want:  "from:alice@example.com",
		},
		{
			name:  "uppercase name",
			hName: "SUBJECT",
			value: " Test \r\n",
			want:  "subject:Test",
		},
		{
			name:  "folded",
			hName: "Subject",
			value: " A very long\r\n subject line\r\n",
			want:  "subject:A very long subject line",
		},
		{
			name:  "multiple spaces",
			hName: "X-Test",
			value: "  a   b  c  \r\n",
			want:  "x-test:a b c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonHeaderRelaxed(tt.hName, tt.value)
			if got != tt.want {
				t.Errorf("canonHeaderRelaxed() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestCanonBodyRelaxed tests relaxed body canonicalization.
func TestCanonBodyRelaxed(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"simple", "Hello\r\n", "Hello\r\n"},
		{"trailing spaces", "Hello  \r\nWorld  \r\n", "Hello\r\nWorld\r\n"},
		{"trailing empty lines", "Hello\r\n\r\n\r\n", "Hello\r\n"},
		{"empty", "", ""},
		{"only whitespace", "   \r\n\r\n", ""},
		{"tabs to spaces", "a\tb\r\n", "a b\r\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(canonBodyRelaxed([]byte(tt.body)))
			if got != tt.want {
				t.Errorf("canonBodyRelaxed() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBodyHashRelaxed tests body hash computation.
func TestBodyHashRelaxed(t *testing.T) {
	// Empty body should hash the empty string per RFC 6376
	emptyHash := bodyHashRelaxed(nil)
	if emptyHash == "" {
		t.Error("bodyHashRelaxed(nil) should return a hash")
	}

	// Same content, different whitespace should produce same hash
	body1 := []byte("Hello  \r\nWorld  \r\n")
	body2 := []byte("Hello\r\nWorld\r\n")
	hash1 := bodyHashRelaxed(body1)
	hash2 := bodyHashRelaxed(body2)
	if hash1 != hash2 {
		t.Errorf("relaxed bodies should have same hash: %s vs %s", hash1, hash2)
	}
}

// TestCollapseWSP tests whitespace collapsing.
func TestCollapseWSP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"a b c", "a b c"},
		{"a  b  c", "a b c"},
		{"a\tb\tc", "a b c"},
		{"a \t b", "a b"},
		{"  leading", " leading"},
		{"trailing  ", "trailing "},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := collapseWSP(tt.input)
			if got != tt.want {
				t.Errorf("collapseWSP(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestParseTagList tests DKIM/ARC tag list parsing.
func TestParseTagList(t *testing.T) {
	input := " a=1; b=2 ; c = 3 "
	got := parseTagList(input)

	if got["a"] != "1" {
		t.Errorf("got[a] = %q, want %q", got["a"], "1")
	}
	if got["b"] != "2" {
		t.Errorf("got[b] = %q, want %q", got["b"], "2")
	}
	if got["c"] != "3" {
		t.Errorf("got[c] = %q, want %q", got["c"], "3")
	}
}

// TestPresentSignedHeaders tests header selection.
func TestPresentSignedHeaders(t *testing.T) {
	fields := []headerField{
		{name: "From", value: " alice@example.com\r\n"},
		{name: "To", value: " bob@example.org\r\n"},
		{name: "X-Custom", value: " custom\r\n"},
		{name: "Subject", value: " Test\r\n"},
	}

	got := presentSignedHeaders(fields)

	// Should include From, To, Subject but not X-Custom
	expected := []string{"From", "To", "Subject"}
	if len(got) != len(expected) {
		t.Errorf("presentSignedHeaders() = %v, want %v", got, expected)
	}
	for i, h := range expected {
		if i >= len(got) || got[i] != h {
			t.Errorf("presentSignedHeaders()[%d] = %q, want %q", i, got[i], h)
		}
	}
}

// mockForwarder implements Forwarder for testing.
type mockForwarder struct {
	from, to string
	msg      []byte
	err      error
}

func (m *mockForwarder) Forward(_ context.Context, from, to string, msg io.Reader) error {
	if m.err != nil {
		return m.err
	}
	m.from = from
	m.to = to
	m.msg, _ = io.ReadAll(msg)
	return nil
}

// TestSMTPForwarder_Interface verifies SMTPForwarder implements Forwarder.
func TestSMTPForwarder_Interface(t *testing.T) {
	var _ Forwarder = (*SMTPForwarder)(nil)
}

// TestNewSMTPForwarder tests constructor.
func TestNewSMTPForwarder(t *testing.T) {
	f := NewSMTPForwarder("localhost:25")
	if f.Addr != "localhost:25" {
		t.Errorf("Addr = %q, want %q", f.Addr, "localhost:25")
	}
}

// TestNewARCSealer tests constructor.
func TestNewARCSealer(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	sealer := NewARCSealer("example.com", "arc", key)

	if sealer.domain != "example.com" {
		t.Errorf("domain = %q, want %q", sealer.domain, "example.com")
	}
	if sealer.selector != "arc" {
		t.Errorf("selector = %q, want %q", sealer.selector, "arc")
	}
	if sealer.key != key {
		t.Error("key not set correctly")
	}
	if sealer.now == nil {
		t.Error("now function should not be nil")
	}
}

// TestFindHeader tests case-insensitive header lookup.
func TestFindHeader(t *testing.T) {
	fields := []headerField{
		{name: "From", value: " alice@example.com\r\n"},
		{name: "TO", value: " bob@example.org\r\n"},
	}

	if v, ok := findHeader(fields, "from"); !ok || !strings.Contains(v, "alice") {
		t.Error("findHeader(from) failed")
	}
	if v, ok := findHeader(fields, "To"); !ok || !strings.Contains(v, "bob") {
		t.Error("findHeader(To) failed")
	}
	if _, ok := findHeader(fields, "Subject"); ok {
		t.Error("findHeader(Subject) should not find anything")
	}
}

// TestParseHeaderFields tests header parsing with folded lines.
func TestParseHeaderFields(t *testing.T) {
	block := "From: alice@example.com\r\n" +
		"Subject: A long\r\n" +
		" subject line\r\n" +
		"To: bob@example.org\r\n"

	fields := parseHeaderFields([]byte(block))

	if len(fields) != 3 {
		t.Fatalf("expected 3 fields, got %d", len(fields))
	}

	// Subject should include the folded continuation
	subjVal, ok := findHeader(fields, "Subject")
	if !ok {
		t.Fatal("Subject header not found")
	}
	if !strings.Contains(subjVal, "long") || !strings.Contains(subjVal, "subject line") {
		t.Errorf("Subject value = %q, should contain folded content", subjVal)
	}
}

// mockMappingResolver implements MappingResolver for testing.
type mockMappingResolver struct {
	realEmail string
	err       error
}

func (m *mockMappingResolver) ResolveRealEmail(_ context.Context, _ *Address, _ []byte) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.realEmail, nil
}

// TestForwardAll_Integration tests the end-to-end forwarding flow including
// ARC sealing and message delivery.
func TestForwardAll_Integration(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	forwarder := &mockForwarder{}
	resolver := &mockMappingResolver{realEmail: "alice-real@inbox.example.com"}
	sealer := NewARCSealer("relay.example.com", "arc", key)

	backend := NewBackend(MTAConfig{
		Lookup:          newMockLookup(),
		Domain:          "relay.example.com",
		ARCSealer:       sealer,
		Forwarder:       forwarder,
		MappingResolver: resolver,
		ReturnPath:      "bounces@relay.example.com",
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	// Simulate a validated recipient
	s.recipients = append(s.recipients, &recipientInfo{
		token:      "test-token",
		address:    &Address{Token: "test-token"},
		encMapping: []byte("encrypted"),
	})

	msg := []byte("From: sender@example.com\r\n" +
		"To: test-token@relay.example.com\r\n" +
		"Subject: Test\r\n" +
		"\r\n" +
		"Hello, World!\r\n")

	authResult := &AuthResult{
		SPF:       AuthPass,
		SPFDomain: "example.com",
		DKIM:      AuthPass,
		DMARC:     AuthPass,
	}

	err = s.forwardAll(context.Background(), msg, authResult)
	if err != nil {
		t.Fatalf("forwardAll() error: %v", err)
	}

	// Verify the forwarder received the message
	if forwarder.from != "bounces@relay.example.com" {
		t.Errorf("from = %q, want %q", forwarder.from, "bounces@relay.example.com")
	}
	if forwarder.to != "alice-real@inbox.example.com" {
		t.Errorf("to = %q, want %q", forwarder.to, "alice-real@inbox.example.com")
	}

	// Verify ARC headers were added
	if !strings.HasPrefix(string(forwarder.msg), "ARC-Seal:") {
		t.Error("forwarded message should start with ARC-Seal")
	}
	if !strings.Contains(string(forwarder.msg), "ARC-Message-Signature:") {
		t.Error("forwarded message should contain ARC-Message-Signature")
	}
	if !strings.Contains(string(forwarder.msg), "ARC-Authentication-Results:") {
		t.Error("forwarded message should contain ARC-Authentication-Results")
	}

	// Verify original body is preserved
	if !strings.Contains(string(forwarder.msg), "Hello, World!") {
		t.Error("forwarded message should contain original body")
	}
}

// TestForwardAll_ForwarderError tests that forwarder errors are propagated.
func TestForwardAll_ForwarderError(t *testing.T) {
	forwarder := &mockForwarder{err: errors.New("connection refused")}
	resolver := &mockMappingResolver{realEmail: "alice@example.com"}

	backend := NewBackend(MTAConfig{
		Lookup:          newMockLookup(),
		Domain:          "relay.example.com",
		Forwarder:       forwarder,
		MappingResolver: resolver,
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	s.recipients = append(s.recipients, &recipientInfo{
		token:      "test-token",
		address:    &Address{Token: "test-token"},
		encMapping: []byte("encrypted"),
	})

	msg := []byte("From: sender@example.com\r\n\r\nBody\r\n")
	err := s.forwardAll(context.Background(), msg, nil)

	if err == nil {
		t.Error("forwardAll() should return error when forwarder fails")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error = %v, want to contain 'connection refused'", err)
	}
}

// TestForwardAll_NoForwarder tests that forwarding is skipped gracefully when
// no forwarder is configured (monitoring mode).
func TestForwardAll_NoForwarder(t *testing.T) {
	backend := NewBackend(MTAConfig{
		Lookup:    newMockLookup(),
		Domain:    "relay.example.com",
		Forwarder: nil, // No forwarder configured
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	s.recipients = append(s.recipients, &recipientInfo{
		token:   "test-token",
		address: &Address{Token: "test-token"},
	})

	msg := []byte("From: sender@example.com\r\n\r\nBody\r\n")
	err := s.forwardAll(context.Background(), msg, nil)

	if err != nil {
		t.Errorf("forwardAll() error = %v, want nil (no forwarder)", err)
	}
}

// TestForwardAll_WithoutARC tests forwarding without ARC sealing.
func TestForwardAll_WithoutARC(t *testing.T) {
	forwarder := &mockForwarder{}
	resolver := &mockMappingResolver{realEmail: "alice@example.com"}

	backend := NewBackend(MTAConfig{
		Lookup:          newMockLookup(),
		Domain:          "relay.example.com",
		ARCSealer:       nil, // No ARC sealing
		Forwarder:       forwarder,
		MappingResolver: resolver,
	})

	session, _ := backend.NewSession(nil)
	s := session.(*Session)

	s.recipients = append(s.recipients, &recipientInfo{
		token:      "test-token",
		address:    &Address{Token: "test-token"},
		encMapping: []byte("encrypted"),
	})

	msg := []byte("From: sender@example.com\r\n\r\nBody\r\n")
	err := s.forwardAll(context.Background(), msg, nil)

	if err != nil {
		t.Fatalf("forwardAll() error: %v", err)
	}

	// Message should NOT have ARC headers when sealer is nil
	if strings.Contains(string(forwarder.msg), "ARC-Seal:") {
		t.Error("message should not have ARC headers without sealer")
	}

	// Original message should be forwarded as-is (with CRLF normalization)
	if !strings.Contains(string(forwarder.msg), "Body") {
		t.Error("forwarded message should contain original body")
	}
}
