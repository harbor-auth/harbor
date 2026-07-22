package relay

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"net/mail"
	"strings"
)

// The reply-through (egress) path lets a user reply to a relayed message from
// their real inbox WITHOUT ever exposing that real address to the other party.
//
// Mechanism: when the relay forwards an inbound message to the user, the
// From/Reply-To it presents is a signed "wrapped" reply address that encodes
// (relay token, original external sender). When the user replies, that wrapped
// address is the RCPT TO. The MTA decodes it, proves the sender owns the relay
// address (envelope MAIL FROM must equal the mapped real email), rewrites the
// reply's From header to the relay address, and sends it outbound to the
// external party. The external party only ever sees the relay address.

// replyPrefix marks a local-part as a wrapped reply address. A normal relay
// token is base64url and never contains a '.', so a wrapped address
// ("rp.<payload>.<sig>") can never collide with a real token.
const replyPrefix = "rp"

// b32 is a lowercase, unpadded base32 codec. base32's alphabet is
// case-insensitive, so the encoding survives the MTA lowercasing the recipient
// local-part (base64url would not, since it is case-sensitive).
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrInvalidReplyAddress is returned when a local-part is not a valid, correctly
// signed wrapped reply address.
var ErrInvalidReplyAddress = errors.New("relay: invalid reply address")

// ReplyAddressCodec encodes and decodes signed wrapped reply addresses. The
// HMAC signature makes the address unforgeable, so an attacker cannot invent a
// reply address for an arbitrary (token, recipient) pair.
type ReplyAddressCodec struct {
	key []byte
}

// NewReplyAddressCodec returns a codec that signs wrapped reply addresses with
// the given secret key.
func NewReplyAddressCodec(key []byte) *ReplyAddressCodec {
	return &ReplyAddressCodec{key: key}
}

// Encode returns the local-part of a wrapped reply address encoding the relay
// token and the external recipient the user is replying to.
func (c *ReplyAddressCodec) Encode(relayToken, recipient string) string {
	payload := []byte(relayToken + "\x00" + recipient)
	p := strings.ToLower(b32.EncodeToString(payload))
	sig := strings.ToLower(b32.EncodeToString(c.mac(p)))
	return replyPrefix + "." + p + "." + sig
}

// FormatReplyAddress returns the full wrapped reply email address
// (local-part@domain) suitable for presenting as a From/Reply-To.
func (c *ReplyAddressCodec) FormatReplyAddress(relayToken, recipient, domain string) string {
	return c.Encode(relayToken, recipient) + "@" + domain
}

// Decode parses and verifies a wrapped reply address local-part, returning the
// relay token and external recipient. It returns ErrInvalidReplyAddress when the
// local-part is not a wrapped reply address or its signature does not verify.
func (c *ReplyAddressCodec) Decode(localPart string) (relayToken, recipient string, err error) {
	parts := strings.Split(localPart, ".")
	if len(parts) != 3 || parts[0] != replyPrefix {
		return "", "", ErrInvalidReplyAddress
	}
	p, sig := parts[1], parts[2]

	gotSig, err := b32.DecodeString(strings.ToUpper(sig))
	if err != nil {
		return "", "", ErrInvalidReplyAddress
	}
	if !hmac.Equal(gotSig, c.mac(p)) {
		return "", "", ErrInvalidReplyAddress
	}

	payload, err := b32.DecodeString(strings.ToUpper(p))
	if err != nil {
		return "", "", ErrInvalidReplyAddress
	}
	i := bytes.IndexByte(payload, 0)
	if i < 0 {
		return "", "", ErrInvalidReplyAddress
	}
	return string(payload[:i]), string(payload[i+1:]), nil
}

// mac computes a truncated HMAC-SHA256 over the encoded payload string. 10 bytes
// (80 bits) is ample to make forgery infeasible while keeping the address short.
func (c *ReplyAddressCodec) mac(p string) []byte {
	h := hmac.New(sha256.New, c.key)
	h.Write([]byte(p))
	return h.Sum(nil)[:10]
}

// replyDropHeaders is the set of headers stripped from a reply during rewrite.
// They either leak the user's real address (Sender, Return-Path, Reply-To,
// X-Original-From) or are cryptographic assertions that no longer hold once the
// From header changes (DKIM-Signature, ARC-*, Authentication-Results) and could
// otherwise be replayed to spoof authentication.
var replyDropHeaders = map[string]bool{
	"sender":                     true,
	"return-path":                true,
	"reply-to":                   true,
	"x-original-from":            true,
	"dkim-signature":             true,
	"authentication-results":     true,
	"arc-seal":                   true,
	"arc-message-signature":      true,
	"arc-authentication-results": true,
}

// ReplyRewriter rewrites a user's outbound reply so it egresses from the relay
// address instead of the user's real address, preserving threading.
type ReplyRewriter struct{}

// NewReplyRewriter returns a ReplyRewriter.
func NewReplyRewriter() *ReplyRewriter { return &ReplyRewriter{} }

// Rewrite returns a copy of msg with the From header rewritten to relayAddr and
// all real-address leak vectors removed. Threading headers (In-Reply-To,
// References, Message-ID) and the body are preserved verbatim. The input is
// never modified, logged, or persisted (§7.5.6).
func (rw *ReplyRewriter) Rewrite(msg []byte, relayAddr string) ([]byte, error) {
	if relayAddr == "" {
		return nil, errors.New("relay: empty relay address for reply rewrite")
	}

	norm := normalizeCRLF(msg)
	fields, body := splitHeadersBody(norm)

	var out bytes.Buffer
	out.Grow(len(norm))
	fromSeen := false
	for _, f := range fields {
		name := strings.ToLower(strings.TrimSpace(f.name))
		switch {
		case name == "from":
			out.WriteString(f.name + ":" + rewriteFromValue(f.value, relayAddr))
			fromSeen = true
		case replyDropHeaders[name]:
			// Drop leak vectors and now-invalid authentication headers.
		default:
			out.WriteString(f.name + ":" + f.value)
		}
	}
	if !fromSeen {
		out.WriteString("From:" + rewriteFromValue("", relayAddr))
	}

	// Blank line terminating the header block, then the untouched body.
	out.WriteString("\r\n")
	out.Write(body)
	return out.Bytes(), nil
}

// rewriteFromValue produces a replacement From header value (leading space,
// trailing CRLF) that keeps the original display name but swaps the addr-spec
// for the relay address.
func rewriteFromValue(raw, relayAddr string) string {
	v := strings.ReplaceAll(raw, "\r\n", "")
	v = strings.ReplaceAll(v, "\n", "")
	v = strings.TrimSpace(v)

	name := ""
	if a, err := mail.ParseAddress(v); err == nil {
		name = a.Name
	}
	return " " + (&mail.Address{Name: name, Address: relayAddr}).String() + "\r\n"
}
