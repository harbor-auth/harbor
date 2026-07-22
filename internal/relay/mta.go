package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"

	"github.com/emersion/go-smtp"

	"github.com/harbor/harbor/internal/region"
)

// MTA-related constants and documentation.
// Errors are returned as *smtp.SMTPError with appropriate SMTP status codes:
//   - 550 (5.1.1): Unknown recipient or deactivated address (hard bounce)
//   - 451 (4.3.0): Temporary failure (database errors)
//   - 452 (4.5.3): Too many recipients
//   - 503 (5.5.1): Bad sequence (DATA without recipients)

// AddressLookup is the interface the MTA needs to look up relay addresses.
// This is a narrow interface to keep the MTA testable with a fake.
type AddressLookup interface {
	// GetByToken retrieves a relay address by its token.
	// Returns ErrRelayAddressNotFound if the token doesn't exist.
	GetByToken(ctx context.Context, token string) (*Address, []byte, error)
}

// MTAConfig configures the inbound MTA server.
type MTAConfig struct {
	// Lookup provides relay address lookups.
	Lookup AddressLookup
	// Logger for operational logging (no PII logged).
	Logger *slog.Logger
	// Domain is the relay domain suffix (e.g., "relay.EU.harbor.id").
	// Used to validate recipient addresses.
	Domain string
	// MaxRecipients is the maximum number of recipients per message (default: 1).
	// Relay addresses are per-user, so typically only one recipient per message.
	MaxRecipients int
	// MaxMessageBytes is the maximum message size in bytes (default: 25MB).
	MaxMessageBytes int64
	// Authenticator verifies SPF/DKIM/DMARC for inbound messages. When nil,
	// authentication is skipped entirely (messages are accepted without checks).
	Authenticator *Authenticator
	// EnforceAuth causes messages that fail authentication to be rejected with a
	// 550 error. When false (but an Authenticator is set), results are evaluated
	// and logged but never cause a rejection (monitoring mode).
	EnforceAuth bool
	// ARCSealer affixes ARC headers before forwarding (optional). When nil,
	// messages are forwarded without ARC sealing.
	ARCSealer *ARCSealer
	// Forwarder delivers messages to users' real inboxes. When nil, messages
	// are accepted but not forwarded (useful for testing).
	Forwarder Forwarder
	// MappingResolver resolves relay addresses to real email addresses.
	// Required when Forwarder is set.
	MappingResolver MappingResolver
	// ReturnPath is the envelope sender used for forwarded messages. This
	// should be a relay-owned address so bounces return to the relay.
	ReturnPath string
	// Region is the home region this MTA serves. It is used ONLY as an
	// aggregate, non-PII metric label (never per-user).
	Region region.Region
	// RateLimiter enforces per-address token-bucket rate limiting. When nil,
	// no rate limiting is applied.
	RateLimiter *RateLimiter
	// ReplyCodec decodes signed wrapped reply addresses for the outbound
	// (reply-through) path. When nil, the reply path is disabled and all mail
	// is treated as inbound.
	ReplyCodec *ReplyAddressCodec
	// ReplyRewriter rewrites a user's reply so it egresses from their relay
	// address without leaking the real address. Required for the reply path.
	ReplyRewriter *ReplyRewriter
	// OutboundForwarder delivers rewritten replies to external recipients via
	// the regional outbound SMTP server. Required for the reply path.
	OutboundForwarder Forwarder
}

// Backend implements smtp.Backend for the inbound relay MTA.
// It creates a new session for each incoming SMTP connection.
type Backend struct {
	lookup          AddressLookup
	logger          *slog.Logger
	domain          string
	maxRecipients   int
	maxMsgBytes     int64
	auth            *Authenticator
	enforceAuth     bool
	arcSealer       *ARCSealer
	forwarder       Forwarder
	mappingResolver MappingResolver
	returnPath      string
	region          region.Region
	rateLimiter     *RateLimiter
	replyCodec      *ReplyAddressCodec
	replyRewriter   *ReplyRewriter
	outboundFwd     Forwarder
}

// NewBackend creates a new SMTP backend for the relay MTA.
func NewBackend(cfg MTAConfig) *Backend {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	maxRecipients := cfg.MaxRecipients
	if maxRecipients <= 0 {
		maxRecipients = 1
	}
	maxMsgBytes := cfg.MaxMessageBytes
	if maxMsgBytes <= 0 {
		maxMsgBytes = 25 * 1024 * 1024 // 25MB default
	}
	return &Backend{
		lookup:          cfg.Lookup,
		logger:          logger,
		domain:          strings.ToLower(cfg.Domain),
		maxRecipients:   maxRecipients,
		maxMsgBytes:     maxMsgBytes,
		auth:            cfg.Authenticator,
		enforceAuth:     cfg.EnforceAuth,
		arcSealer:       cfg.ARCSealer,
		forwarder:       cfg.Forwarder,
		mappingResolver: cfg.MappingResolver,
		returnPath:      cfg.ReturnPath,
		region:          cfg.Region,
		rateLimiter:     cfg.RateLimiter,
		replyCodec:      cfg.ReplyCodec,
		replyRewriter:   cfg.ReplyRewriter,
		outboundFwd:     cfg.OutboundForwarder,
	}
}

// NewSession implements smtp.Backend. Called for each new SMTP connection.
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{
		backend:    b,
		conn:       c,
		recipients: make([]*recipientInfo, 0, 1),
	}, nil
}

// recipientInfo holds information about a validated recipient.
type recipientInfo struct {
	token      string
	address    *Address
	encMapping []byte // envelope-encrypted real email mapping
}

// replyInfo holds a staged reply-through delivery: the relay address to rewrite
// the user's From header to, and the external recipient to deliver to.
type replyInfo struct {
	relayAddr    string // token@relay.<domain> — the From to present outbound
	extRecipient string // external party the user is replying to
}

// Session implements smtp.Session for a single SMTP connection.
// It handles the SMTP transaction: MAIL FROM, RCPT TO, DATA.
//
// Privacy note (§7.5.6): No message content is retained. The Data method
// reads and discards the message body after processing. Only minimal
// routing metadata is kept in memory during the transaction.
//
// Note: The `from`, `helo`, and `remoteIP` fields feed SPF/DMARC validation.
// The `recipientInfo.address` field is staged for forwarding in a later task.
type Session struct {
	backend    *Backend
	conn       *smtp.Conn       // Underlying connection (nil in unit tests)
	from       string           // Envelope sender (MAIL FROM), used for SPF
	helo       string           // HELO/EHLO hostname, SPF fallback for null senders
	remoteIP   net.IP           // Connecting client IP, used for SPF
	recipients []*recipientInfo // Validated recipients for forwarding
	replies    []*replyInfo     // Staged reply-through (egress) deliveries
}

// Reset implements smtp.Session. Called when the client sends RSET.
// Only transaction-level state (envelope sender, recipients) is cleared;
// connection-level state (HELO, remote IP) persists across RSET.
func (s *Session) Reset() {
	s.from = ""
	s.recipients = s.recipients[:0]
	s.replies = s.replies[:0]
}

// populateConnInfo lazily fills the remote IP and HELO hostname from the
// underlying connection. It is a no-op when there is no connection (unit tests
// may set s.remoteIP / s.helo directly instead).
func (s *Session) populateConnInfo() {
	if s.conn == nil {
		return
	}
	if s.remoteIP == nil {
		if tcp, ok := s.conn.Conn().RemoteAddr().(*net.TCPAddr); ok {
			s.remoteIP = tcp.IP
		}
	}
	if s.helo == "" {
		s.helo = s.conn.Hostname()
	}
}

// Logout implements smtp.Session. Called when the client disconnects.
func (s *Session) Logout() error {
	return nil
}

// Mail implements smtp.Session. Called for MAIL FROM command.
func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	s.from = from
	return nil
}

// Rcpt implements smtp.Session. Called for each RCPT TO command.
// Validates that the recipient is a known, active relay address.
// Returns a 550 error for unknown or deactivated addresses (hard bounce).
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	// Check recipient limit
	if len(s.recipients) >= s.backend.maxRecipients {
		return &smtp.SMTPError{
			Code:         452,
			EnhancedCode: smtp.EnhancedCode{4, 5, 3},
			Message:      "too many recipients",
		}
	}

	// Parse the recipient address to extract the token
	token, err := s.parseRecipient(to)
	if err != nil {
		// Log at debug level — unknown addresses are normal (typos, spam probes)
		s.backend.logger.Debug("relay: invalid recipient format",
			slog.String("error", err.Error()))
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 1, 1},
			Message:      "recipient not found",
		}
	}

	// Reply/egress path: the recipient local-part may be a signed wrapped reply
	// address, meaning a user is replying THROUGH their relay address. If it
	// decodes, handle it here rather than as an inbound delivery.
	if s.backend.replyCodec != nil {
		if relayToken, extRecipient, dErr := s.backend.replyCodec.Decode(token); dErr == nil {
			return s.stageReply(context.Background(), relayToken, extRecipient)
		}
	}

	// Look up the relay address
	ctx := context.Background()
	addr, encMapping, err := s.backend.lookup.GetByToken(ctx, token)
	if err != nil {
		if errors.Is(err, ErrRelayAddressNotFound) {
			s.backend.logger.Debug("relay: unknown recipient token")
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 1, 1},
				Message:      "recipient not found",
			}
		}
		// Database error — temporary failure
		s.backend.logger.Error("relay: lookup failed", slog.Any("error", err))
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "temporary failure, please retry",
		}
	}

	// Check if the address can receive mail (Active or BYO-domain state)
	if !addr.CanReceiveMail() {
		// Deactivated address — hard bounce (§7.5.4 kill switch)
		recordBounced(s.backend.region)
		s.backend.logger.Info("relay: address deactivated, rejecting")
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 1, 1},
			Message:      "recipient no longer accepts mail",
		}
	}

	// Per-address token-bucket rate limiting. Metrics are aggregate-only — no
	// per-address or per-IP series is ever emitted, so abuse is visible without
	// recreating per-user tracking.
	if s.backend.rateLimiter != nil && !s.backend.rateLimiter.Allow(token) {
		recordRateLimited(s.backend.region)
		s.backend.logger.Info("relay: address rate limited")
		return &smtp.SMTPError{
			Code:         450,
			EnhancedCode: smtp.EnhancedCode{4, 7, 1},
			Message:      "rate limit exceeded, please retry later",
		}
	}

	// Valid recipient — store for DATA phase
	s.recipients = append(s.recipients, &recipientInfo{
		token:      token,
		address:    addr,
		encMapping: encMapping,
	})
	return nil
}

// parseRecipient extracts the relay token from a recipient address.
// Expected format: <token>@relay.<region>.harbor.id or <token>@<byo-domain>
func (s *Session) parseRecipient(to string) (string, error) {
	// Normalize to lowercase for comparison
	to = strings.ToLower(strings.TrimSpace(to))

	// Find the @ separator
	atIdx := strings.LastIndex(to, "@")
	if atIdx <= 0 || atIdx >= len(to)-1 {
		return "", errors.New("invalid address format")
	}

	localPart := to[:atIdx]
	domain := to[atIdx+1:]

	// Validate domain matches our relay domain
	// For now, require exact match; BYO-domain support comes in Phase 2
	if s.backend.domain != "" && domain != s.backend.domain {
		return "", errors.New("domain mismatch")
	}

	// The local part is the relay token
	if localPart == "" {
		return "", errors.New("empty local part")
	}

	return localPart, nil
}

// Data implements smtp.Session. Called when the client sends DATA.
// This is where we forward the message to the user's real inbox.
//
// Privacy note (§7.5.6): The message body is read but NOT retained.
// No logging of message content occurs. Only minimal routing metadata
// is kept in memory during processing. The message is buffered transiently
// for ARC sealing and forwarding, then immediately discarded.
func (s *Session) Data(r io.Reader) error {
	if len(s.recipients) == 0 && len(s.replies) == 0 {
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "no valid recipients",
		}
	}

	// Reply-through (egress) path takes precedence when the transaction was
	// addressed to a wrapped reply address.
	if len(s.replies) > 0 {
		return s.handleReply(context.Background(), r)
	}

	// Fast path: when no authenticator is configured, read and discard the body
	// without retaining any content (§7.5.6).
	if s.backend.auth == nil {
		if _, err := io.Copy(io.Discard, r); err != nil {
			s.backend.logger.Error("relay: failed to read message body",
				slog.Any("error", err))
			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 3, 0},
				Message:      "temporary failure reading message",
			}
		}
		recordAccepted(s.backend.region)
		s.backend.logger.Info("relay: message accepted",
			slog.Int("recipient_count", len(s.recipients)))
		return nil
	}

	// Buffer the message transiently in memory for authentication. The buffer is
	// discarded when this method returns and is never persisted (§7.5.6).
	msg, err := io.ReadAll(io.LimitReader(r, s.backend.maxMsgBytes))
	if err != nil {
		s.backend.logger.Error("relay: failed to read message body",
			slog.Any("error", err))
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "temporary failure reading message",
		}
	}

	s.populateConnInfo()
	result, err := s.backend.auth.Authenticate(context.Background(), AuthInput{
		RemoteIP: s.remoteIP,
		MailFrom: s.from,
		Helo:     s.helo,
		Message:  msg,
	})
	if err != nil {
		s.backend.logger.Error("relay: authentication error", slog.Any("error", err))
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 7, 0},
			Message:      "temporary authentication failure, please retry",
		}
	}

	if s.backend.enforceAuth && result.ShouldReject() {
		// Do not log PII (sender/recipient). Only aggregate auth verdicts.
		s.backend.logger.Info("relay: message rejected by authentication policy",
			slog.String("spf", string(result.SPF)),
			slog.String("dkim", string(result.DKIM)),
			slog.String("dmarc", string(result.DMARC)))
		recordBounced(s.backend.region)
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "message failed sender authentication (SPF/DKIM/DMARC)",
		}
	}

	// ARC-seal and forward the message to each recipient's real inbox.
	// The message buffer is discarded when this method returns (§7.5.6).
	if err := s.forwardAll(context.Background(), msg, result); err != nil {
		s.backend.logger.Error("relay: forwarding failed", slog.Any("error", err))
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 4, 1},
			Message:      "temporary forwarding failure, please retry",
		}
	}

	recordAccepted(s.backend.region)

	// Log acceptance with auth verdicts (no PII — only aggregate results).
	s.backend.logger.Info("relay: message accepted and forwarded",
		slog.Int("recipient_count", len(s.recipients)),
		slog.String("spf", string(result.SPF)),
		slog.String("dkim", string(result.DKIM)),
		slog.String("dmarc", string(result.DMARC)))

	return nil
}

// forwardAll ARC-seals and forwards the message to each recipient's real inbox.
// It resolves the encrypted mapping to the real email just-in-time and discards
// the plaintext immediately after forwarding. Returns the first error encountered.
func (s *Session) forwardAll(ctx context.Context, msg []byte, authResult *AuthResult) error {
	// Skip forwarding if no forwarder is configured (test/monitoring mode).
	if s.backend.forwarder == nil {
		return nil
	}

	// ARC-seal the message once (same sealed copy goes to all recipients).
	sealed := msg
	if s.backend.arcSealer != nil {
		var err error
		sealed, err = s.backend.arcSealer.Seal(msg, authResult)
		if err != nil {
			return err
		}
	}

	// Use a relay-owned return-path so bounces come back to us and outbound
	// SPF passes for the relay domain.
	returnPath := s.backend.returnPath
	if returnPath == "" {
		returnPath = "bounces@" + s.backend.domain
	}

	for _, rcpt := range s.recipients {
		// Resolve the real email just-in-time; keep plaintext in memory only
		// for the duration of the Forward call.
		if s.backend.mappingResolver == nil {
			continue // no resolver — skip (shouldn't happen in production)
		}
		realEmail, err := s.backend.mappingResolver.ResolveRealEmail(ctx, rcpt.address, rcpt.encMapping)
		if err != nil {
			return err
		}

		// Forward the sealed message. The body is streamed and never persisted.
		if err := s.backend.forwarder.Forward(ctx, returnPath, realEmail, bytes.NewReader(sealed)); err != nil {
			return err
		}
		recordForwarded(s.backend.region)
	}
	return nil
}

// stageReply validates a reply-through (egress) transaction and stages it for
// the DATA phase. It proves the sender owns the relay address — only the mapped
// real mailbox may send AS a relay address — before allowing the rewrite.
func (s *Session) stageReply(ctx context.Context, relayToken, extRecipient string) error {
	addr, encMapping, err := s.backend.lookup.GetByToken(ctx, relayToken)
	if err != nil {
		if errors.Is(err, ErrRelayAddressNotFound) {
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 1, 1},
				Message:      "recipient not found",
			}
		}
		s.backend.logger.Error("relay: reply lookup failed", slog.Any("error", err))
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "temporary failure, please retry",
		}
	}
	if !addr.CanReceiveMail() {
		recordBounced(s.backend.region)
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 1, 1},
			Message:      "relay address no longer active",
		}
	}

	// Ownership check: the envelope sender MUST be the real mailbox mapped to
	// this relay address. Without a resolver we cannot prove ownership, so the
	// reply is refused rather than risk letting anyone spoof a relay identity.
	if s.backend.mappingResolver == nil {
		s.backend.logger.Error("relay: reply path misconfigured (no mapping resolver)")
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "temporary failure, please retry",
		}
	}
	realEmail, err := s.backend.mappingResolver.ResolveRealEmail(ctx, addr, encMapping)
	if err != nil {
		s.backend.logger.Error("relay: reply mapping resolve failed", slog.Any("error", err))
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "temporary failure, please retry",
		}
	}
	if !addrEqualFold(s.from, realEmail) {
		recordBounced(s.backend.region)
		s.backend.logger.Info("relay: reply sender not authorized for relay address")
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "not authorized to send from this relay address",
		}
	}

	// Rate-limit egress per relay address too (same token-bucket as inbound).
	if s.backend.rateLimiter != nil && !s.backend.rateLimiter.Allow(relayToken) {
		recordRateLimited(s.backend.region)
		s.backend.logger.Info("relay: reply address rate limited")
		return &smtp.SMTPError{
			Code:         450,
			EnhancedCode: smtp.EnhancedCode{4, 7, 1},
			Message:      "rate limit exceeded, please retry later",
		}
	}

	s.replies = append(s.replies, &replyInfo{
		relayAddr:    relayToken + "@" + s.backend.domain,
		extRecipient: extRecipient,
	})
	return nil
}

// handleReply reads the user's reply, rewrites its From header to the relay
// address (scrubbing every real-address leak vector), and delivers it to the
// external recipient via the regional outbound SMTP server. The body is held in
// a single transient buffer and discarded when this method returns (§7.5.6).
func (s *Session) handleReply(ctx context.Context, r io.Reader) error {
	if s.backend.outboundFwd == nil || s.backend.replyRewriter == nil {
		// Drain the body so the client isn't left hanging, then fail.
		_, _ = io.Copy(io.Discard, io.LimitReader(r, s.backend.maxMsgBytes))
		s.backend.logger.Error("relay: reply path misconfigured (no rewriter/forwarder)")
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "temporary failure, please retry",
		}
	}

	msg, err := io.ReadAll(io.LimitReader(r, s.backend.maxMsgBytes))
	if err != nil {
		s.backend.logger.Error("relay: failed to read reply body", slog.Any("error", err))
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "temporary failure reading message",
		}
	}

	returnPath := s.backend.returnPath
	if returnPath == "" {
		returnPath = "bounces@" + s.backend.domain
	}

	for _, rep := range s.replies {
		rewritten, err := s.backend.replyRewriter.Rewrite(msg, rep.relayAddr)
		if err != nil {
			s.backend.logger.Error("relay: reply rewrite failed", slog.Any("error", err))
			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 3, 0},
				Message:      "temporary failure processing message",
			}
		}
		if err := s.backend.outboundFwd.Forward(ctx, returnPath, rep.extRecipient, bytes.NewReader(rewritten)); err != nil {
			s.backend.logger.Error("relay: reply delivery failed", slog.Any("error", err))
			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 4, 1},
				Message:      "temporary delivery failure, please retry",
			}
		}
		recordReplied(s.backend.region)
	}

	// No PII — only an aggregate count of reply-through deliveries.
	s.backend.logger.Info("relay: reply sent outbound",
		slog.Int("reply_count", len(s.replies)))
	return nil
}

// addrEqualFold reports whether two email addresses are equal, ignoring case,
// surrounding whitespace, and angle brackets.
func addrEqualFold(a, b string) bool {
	norm := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimPrefix(s, "<")
		s = strings.TrimSuffix(s, ">")
		return strings.ToLower(strings.TrimSpace(s))
	}
	return norm(a) != "" && norm(a) == norm(b)
}

// NewServer creates and configures an SMTP server for the relay MTA.
// The server is not started — call ListenAndServe on the returned server.
func NewServer(cfg MTAConfig) *smtp.Server {
	backend := NewBackend(cfg)

	s := smtp.NewServer(backend)
	s.Domain = cfg.Domain
	s.AllowInsecureAuth = false
	s.MaxMessageBytes = backend.maxMsgBytes
	s.MaxRecipients = backend.maxRecipients

	return s
}
