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
}

// Reset implements smtp.Session. Called when the client sends RSET.
// Only transaction-level state (envelope sender, recipients) is cleared;
// connection-level state (HELO, remote IP) persists across RSET.
func (s *Session) Reset() {
	s.from = ""
	s.recipients = s.recipients[:0]
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
		s.backend.logger.Info("relay: address deactivated, rejecting")
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 1, 1},
			Message:      "recipient no longer accepts mail",
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
//
// TODO: Rate limiting (Task 12)
func (s *Session) Data(r io.Reader) error {
	if len(s.recipients) == 0 {
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "no valid recipients",
		}
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
	}
	return nil
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
