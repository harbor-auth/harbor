package relay

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/emersion/go-smtp"

	"github.com/harbor/harbor/internal/region"
)

// --- Reply address codec ---------------------------------------------------

func TestReplyAddressCodec_RoundTrip(t *testing.T) {
	c := NewReplyAddressCodec([]byte("secret-key"))

	local := c.Encode("tok123", "ext@example.com")
	token, recipient, err := c.Decode(local)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}
	if token != "tok123" {
		t.Errorf("token = %q, want %q", token, "tok123")
	}
	if recipient != "ext@example.com" {
		t.Errorf("recipient = %q, want %q", recipient, "ext@example.com")
	}
}

func TestReplyAddressCodec_SurvivesLowercasing(t *testing.T) {
	// The MTA lowercases recipient local-parts; the encoding must survive it.
	c := NewReplyAddressCodec([]byte("secret-key"))
	local := c.Encode("tok123", "ext@example.com")

	token, recipient, err := c.Decode(strings.ToLower(local))
	if err != nil {
		t.Fatalf("Decode(lowercased) error: %v", err)
	}
	if token != "tok123" || recipient != "ext@example.com" {
		t.Errorf("round trip mismatch: token=%q recipient=%q", token, recipient)
	}
}

func TestReplyAddressCodec_RejectsTamperedSignature(t *testing.T) {
	c := NewReplyAddressCodec([]byte("secret-key"))
	local := c.Encode("tok123", "ext@example.com")

	// Flip the last character of the signature.
	tampered := local[:len(local)-1]
	if local[len(local)-1] == 'a' {
		tampered += "b"
	} else {
		tampered += "a"
	}
	if _, _, err := c.Decode(tampered); err == nil {
		t.Error("Decode() accepted a tampered signature, want error")
	}
}

func TestReplyAddressCodec_RejectsWrongKey(t *testing.T) {
	local := NewReplyAddressCodec([]byte("key-a")).Encode("tok123", "ext@example.com")
	if _, _, err := NewReplyAddressCodec([]byte("key-b")).Decode(local); err == nil {
		t.Error("Decode() with wrong key succeeded, want error")
	}
}

func TestReplyAddressCodec_RejectsNonReplyLocalPart(t *testing.T) {
	c := NewReplyAddressCodec([]byte("secret-key"))
	// A normal base64url relay token — not a wrapped reply address.
	if _, _, err := c.Decode("abcDEF-_123"); err == nil {
		t.Error("Decode() accepted a plain token, want error")
	}
}

// --- Reply rewriter --------------------------------------------------------

const realEmail = "alice@real.example"

func sampleReply() string {
	return "From: Alice <" + realEmail + ">\r\n" +
		"Sender: " + realEmail + "\r\n" +
		"Reply-To: " + realEmail + "\r\n" +
		"Return-Path: <" + realEmail + ">\r\n" +
		"To: ext@example.com\r\n" +
		"Subject: Re: Hello\r\n" +
		"In-Reply-To: <orig-123@example.com>\r\n" +
		"References: <orig-123@example.com>\r\n" +
		"DKIM-Signature: v=1; a=rsa-sha256; d=real.example; b=abc\r\n" +
		"\r\n" +
		"This is my reply.\r\n"
}

func TestReplyRewriter_RewritesFromAndScrubsLeaks(t *testing.T) {
	rw := NewReplyRewriter()
	relayAddr := "tok123@relay.eu.harbor.id"

	out, err := rw.Rewrite([]byte(sampleReply()), relayAddr)
	if err != nil {
		t.Fatalf("Rewrite() error: %v", err)
	}
	got := string(out)

	// The real address must not appear anywhere in the outbound message.
	if strings.Contains(got, realEmail) {
		t.Errorf("rewritten message still contains real address %q:\n%s", realEmail, got)
	}
	// From must be rewritten to the relay address, keeping the display name.
	if !strings.Contains(got, "From:") || !strings.Contains(got, relayAddr) {
		t.Errorf("From header not rewritten to relay address:\n%s", got)
	}
	if !strings.Contains(got, "Alice") {
		t.Errorf("display name not preserved:\n%s", got)
	}
	// Leak vectors and stale auth headers must be gone.
	// Note: we match "\r\nHeaderName:" to avoid false positives like
	// "In-Reply-To:" matching "Reply-To:".
	for _, h := range []string{"Sender:", "Reply-To:", "Return-Path:", "DKIM-Signature:"} {
		// Check for header at start of message or after CRLF.
		if strings.HasPrefix(got, h) || strings.Contains(got, "\r\n"+h) {
			t.Errorf("leak/stale header %q was not stripped:\n%s", h, got)
		}
	}
	// Threading headers and body must be preserved verbatim.
	for _, h := range []string{
		"In-Reply-To: <orig-123@example.com>",
		"References: <orig-123@example.com>",
		"Subject: Re: Hello",
		"This is my reply.",
	} {
		if !strings.Contains(got, h) {
			t.Errorf("expected preserved content %q missing:\n%s", h, got)
		}
	}
}

func TestReplyRewriter_EmptyRelayAddrErrors(t *testing.T) {
	if _, err := NewReplyRewriter().Rewrite([]byte(sampleReply()), ""); err == nil {
		t.Error("Rewrite() with empty relay address should error")
	}
}

// --- MTA reply-through integration -----------------------------------------

type replyStubLookup struct {
	addr *Address
	enc  []byte
	err  error
}

func (l *replyStubLookup) GetByToken(_ context.Context, _ string) (*Address, []byte, error) {
	return l.addr, l.enc, l.err
}

type replyStubResolver struct {
	email string
	err   error
}

func (r *replyStubResolver) ResolveRealEmail(_ context.Context, _ *Address, _ []byte) (string, error) {
	return r.email, r.err
}

type replyStubForwarder struct {
	from string
	to   string
	msg  []byte
}

func (f *replyStubForwarder) Forward(_ context.Context, from, to string, msg io.Reader) error {
	f.from = from
	f.to = to
	f.msg, _ = io.ReadAll(msg)
	return nil
}

func newReplyBackend(t *testing.T, resolverEmail string, fwd *replyStubForwarder) *Backend {
	t.Helper()
	codec := NewReplyAddressCodec([]byte("secret-key"))
	return NewBackend(MTAConfig{
		Lookup:            &replyStubLookup{addr: &Address{Token: "tok123", State: StateActive, Region: region.EU}},
		Domain:            "relay.eu.harbor.id",
		Region:            region.EU,
		MappingResolver:   &replyStubResolver{email: resolverEmail},
		ReplyCodec:        codec,
		ReplyRewriter:     NewReplyRewriter(),
		OutboundForwarder: fwd,
	})
}

func TestSession_ReplyThrough_RewritesAndForwards(t *testing.T) {
	fwd := &replyStubForwarder{}
	b := newReplyBackend(t, realEmail, fwd)
	sess := &Session{backend: b, recipients: make([]*recipientInfo, 0, 1)}

	// User replies from their real inbox.
	if err := sess.Mail(realEmail, nil); err != nil {
		t.Fatalf("Mail() error: %v", err)
	}
	// RCPT TO is the signed wrapped reply address.
	wrapped := b.replyCodec.FormatReplyAddress("tok123", "ext@example.com", b.domain)
	if err := sess.Rcpt(wrapped, nil); err != nil {
		t.Fatalf("Rcpt() error: %v", err)
	}
	if len(sess.replies) != 1 {
		t.Fatalf("expected 1 staged reply, got %d", len(sess.replies))
	}

	if err := sess.Data(strings.NewReader(sampleReply())); err != nil {
		t.Fatalf("Data() error: %v", err)
	}

	// Delivered to the external recipient via the outbound forwarder.
	if fwd.to != "ext@example.com" {
		t.Errorf("outbound to = %q, want %q", fwd.to, "ext@example.com")
	}
	// Envelope sender is the relay-owned return-path, not the real address.
	if fwd.from != "bounces@relay.eu.harbor.id" {
		t.Errorf("outbound from = %q, want relay return-path", fwd.from)
	}
	out := string(fwd.msg)
	if strings.Contains(out, realEmail) {
		t.Errorf("outbound message leaks real address:\n%s", out)
	}
	if !strings.Contains(out, "tok123@relay.eu.harbor.id") {
		t.Errorf("outbound From not rewritten to relay address:\n%s", out)
	}
}

func TestSession_ReplyThrough_RejectsUnauthorizedSender(t *testing.T) {
	fwd := &replyStubForwarder{}
	// The mapped real email differs from the envelope MAIL FROM below.
	b := newReplyBackend(t, realEmail, fwd)
	sess := &Session{backend: b, recipients: make([]*recipientInfo, 0, 1)}

	if err := sess.Mail("attacker@evil.example", nil); err != nil {
		t.Fatalf("Mail() error: %v", err)
	}
	wrapped := b.replyCodec.FormatReplyAddress("tok123", "ext@example.com", b.domain)
	err := sess.Rcpt(wrapped, nil)
	if err == nil {
		t.Fatal("Rcpt() accepted an unauthorized sender, want rejection")
	}
	var smtpErr *smtp.SMTPError
	if !errors.As(err, &smtpErr) || smtpErr.Code != 550 {
		t.Errorf("error = %v, want 550 SMTPError", err)
	}
	if len(sess.replies) != 0 {
		t.Errorf("unauthorized reply was staged: %d", len(sess.replies))
	}
}
