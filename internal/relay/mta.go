package relay

import (
	"context"
	"errors"
	"io"
	"log/slog"
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
}

// Backend implements smtp.Backend for the inbound relay MTA.
// It creates a new session for each incoming SMTP connection.
type Backend struct {
	lookup        AddressLookup
	logger        *slog.Logger
	domain        string
	maxRecipients int
	maxMsgBytes   int64
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
		lookup:        cfg.Lookup,
		logger:        logger,
		domain:        strings.ToLower(cfg.Domain),
		maxRecipients: maxRecipients,
		maxMsgBytes:   maxMsgBytes,
	}
}

// NewSession implements smtp.Backend. Called for each new SMTP connection.
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{
		backend:    b,
		recipients: make([]*recipientInfo, 0, 1),
	}, nil
}

// recipientInfo holds information about a validated recipient.
type recipientInfo struct {
	token   string
	address *Address
}

// Session implements smtp.Session for a single SMTP connection.
// It handles the SMTP transaction: MAIL FROM, RCPT TO, DATA.
//
// Privacy note (§7.5.6): No message content is retained. The Data method
// reads and discards the message body after processing. Only minimal
// routing metadata is kept in memory during the transaction.
//
// Note: The `from` field is staged for SPF validation in a later task.
// The `recipientInfo.address` field is staged for forwarding in a later task.
type Session struct {
	backend    *Backend
	from       string           // Staged for SPF check (Task 10)
	recipients []*recipientInfo // Validated recipients for forwarding
}

// Reset implements smtp.Session. Called when the client sends RSET.
func (s *Session) Reset() {
	s.from = ""
	s.recipients = s.recipients[:0]
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
	addr, _, err := s.backend.lookup.GetByToken(ctx, token)
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
		token:   token,
		address: addr,
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
// This is where we would forward the message to the user's real inbox.
//
// Privacy note (§7.5.6): The message body is read but NOT retained.
// No logging of message content occurs. Only minimal routing metadata
// is kept in memory during processing.
//
// TODO: Implement actual forwarding in a later task:
// - SPF/DKIM/DMARC validation (Task 10)
// - ARC-seal and forward (Task 11)
// - Rate limiting (Task 12)
func (s *Session) Data(r io.Reader) error {
	if len(s.recipients) == 0 {
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "no valid recipients",
		}
	}

	// Read and discard the message body (no content retention per §7.5.6).
	// In the full implementation, this would:
	// 1. Validate SPF/DKIM/DMARC
	// 2. ARC-seal the message
	// 3. Forward to the user's real inbox
	// For now, we just accept the message after validation.
	_, err := io.Copy(io.Discard, r)
	if err != nil {
		s.backend.logger.Error("relay: failed to read message body",
			slog.Any("error", err))
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "temporary failure reading message",
		}
	}

	// Log acceptance (no PII — only counts for aggregate metrics)
	s.backend.logger.Info("relay: message accepted",
		slog.Int("recipient_count", len(s.recipients)))

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
