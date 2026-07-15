package clients

import (
	"context"
	"log/slog"

	"github.com/redis/go-redis/v9"

	"github.com/harbor/harbor/internal/oidc"
)

// DefaultRevocationChannel is the Redis pub/sub channel for emergency JWT
// revocations (docs/DESIGN.md §3.5).
const DefaultRevocationChannel = "revocation_channel"

// RevocationSubscriber listens to the Redis revocation channel and applies
// incoming JTIs to the local bloom filter. This enables near-instant
// cross-replica propagation of emergency revocations (~1ms network latency
// vs 15-minute JWT TTL).
//
// Usage:
//
//	sub := NewRevocationSubscriber(RevocationSubscriberConfig{
//		Client: redisClient,
//		Filter: filter,
//		Logger: logger,
//	})
//	go sub.Run(ctx) // blocks until ctx is cancelled
//
// The subscriber is resilient to transient Redis failures: it logs errors
// and continues. The DB remains the source of truth; on restart, the filter
// is rehydrated from revoked_jtis, so missed pub/sub messages are recovered.
type RevocationSubscriber struct {
	client  *redis.Client
	filter  oidc.RevocationFilter
	channel string
	logger  *slog.Logger
}

// RevocationSubscriberConfig configures a RevocationSubscriber.
type RevocationSubscriberConfig struct {
	// Client is the Redis client for pub/sub. Required.
	Client *redis.Client
	// Filter is the local bloom filter to update. Required.
	Filter oidc.RevocationFilter
	// Channel is the Redis pub/sub channel name. Defaults to
	// DefaultRevocationChannel if empty.
	Channel string
	// Logger for subscription events. Defaults to slog.Default() if nil.
	Logger *slog.Logger
}

// NewRevocationSubscriber creates a subscriber with the given configuration.
// Returns nil if Client or Filter is nil (caller should skip subscription).
func NewRevocationSubscriber(cfg RevocationSubscriberConfig) *RevocationSubscriber {
	if cfg.Client == nil || cfg.Filter == nil {
		return nil
	}
	channel := cfg.Channel
	if channel == "" {
		channel = DefaultRevocationChannel
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &RevocationSubscriber{
		client:  cfg.Client,
		filter:  cfg.Filter,
		channel: channel,
		logger:  logger,
	}
}

// Run subscribes to the revocation channel and processes messages until ctx
// is cancelled. This method blocks; call it in a goroutine.
//
// On each message, the JTI payload is added to the local filter. Invalid
// messages (empty payload) are logged and skipped.
//
// The subscription uses Redis SUBSCRIBE (not PSUBSCRIBE), so only exact
// channel matches are received. On subscription error, Run returns; the
// caller should restart the subscriber or fall back to periodic rehydration.
func (s *RevocationSubscriber) Run(ctx context.Context) error {
	pubsub := s.client.Subscribe(ctx, s.channel)
	defer func() {
		if err := pubsub.Close(); err != nil {
			s.logger.Warn("revocation subscriber: close error", "error", err)
		}
	}()

	// Wait for subscription confirmation before processing messages.
	// This ensures we don't miss messages published after Subscribe returns.
	_, err := pubsub.Receive(ctx)
	if err != nil {
		return err
	}
	s.logger.Info("revocation subscriber: subscribed", "channel", s.channel)

	ch := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("revocation subscriber: shutting down", "reason", ctx.Err())
			return ctx.Err()
		case msg, ok := <-ch:
			if !ok {
				// Channel closed by Redis client (e.g., connection lost).
				s.logger.Warn("revocation subscriber: channel closed")
				return nil
			}
			s.handleMessage(msg)
		}
	}
}

// handleMessage processes a single pub/sub message by adding the JTI to the
// local filter. Empty payloads are logged and skipped.
func (s *RevocationSubscriber) handleMessage(msg *redis.Message) {
	jti := msg.Payload
	if jti == "" {
		s.logger.Warn("revocation subscriber: empty payload, skipping")
		return
	}
	s.filter.Add(jti)
	s.logger.Debug("revocation subscriber: added jti to filter", "jti", jti)
}

// Channel returns the Redis channel this subscriber is listening on.
func (s *RevocationSubscriber) Channel() string {
	return s.channel
}
