package relay

// metrics.go wires the inbound relay MTA into Harbor's zero-PII telemetry facade
// (internal/telemetry). Every instrument here is aggregate-only and partitioned
// STRICTLY by the allow-listed, non-PII region dimension — no relay token, real
// email, user_id, or client IP can ever reach a metric (docs/DESIGN.md §6.5,
// observability-metrics REQ-001/REQ-002). This gives operators accept / bounce /
// forward / rate-limit visibility for abuse detection without any per-user
// behavioural series.

import (
	"github.com/harbor/harbor/internal/region"
	"github.com/harbor/harbor/internal/telemetry"
)

var (
	// relayAcceptedTotal counts inbound messages the relay accepted for delivery.
	relayAcceptedTotal = telemetry.NewCounter(
		"harbor_relay_accepted_total",
		"Inbound relay messages accepted, by region.",
		telemetry.DimRegion,
	)
	// relayBouncedTotal counts inbound messages hard-bounced by the relay
	// (deactivated address kill switch or failed sender authentication).
	relayBouncedTotal = telemetry.NewCounter(
		"harbor_relay_bounced_total",
		"Inbound relay messages hard-bounced (deactivated address or failed auth), by region.",
		telemetry.DimRegion,
	)
	// relayForwardedTotal counts messages successfully delivered to a real inbox.
	relayForwardedTotal = telemetry.NewCounter(
		"harbor_relay_forwarded_total",
		"Relay messages successfully forwarded to a real inbox, by region.",
		telemetry.DimRegion,
	)
	// relayRateLimitedTotal counts inbound messages rejected by per-address
	// rate limiting. It is aggregate-only — there is NO per-address or per-IP
	// series, so abuse is visible without recreating per-user tracking.
	relayRateLimitedTotal = telemetry.NewCounter(
		"harbor_relay_rate_limited_total",
		"Inbound relay messages rejected by per-address rate limiting, by region.",
		telemetry.DimRegion,
	)
	// relayRepliedTotal counts reply-through messages rewritten and sent
	// outbound (the user replying from their relay address).
	relayRepliedTotal = telemetry.NewCounter(
		"harbor_relay_replied_total",
		"Reply-through messages rewritten and sent outbound, by region.",
		telemetry.DimRegion,
	)
)

// recordAccepted meters one accepted inbound message for the region.
func recordAccepted(reg region.Region) { relayAcceptedTotal.Inc(telemetry.Region(reg)) }

// recordBounced meters one hard-bounced inbound message for the region.
func recordBounced(reg region.Region) { relayBouncedTotal.Inc(telemetry.Region(reg)) }

// recordForwarded meters one successful forward to a real inbox for the region.
func recordForwarded(reg region.Region) { relayForwardedTotal.Inc(telemetry.Region(reg)) }

// recordRateLimited meters one rate-limited inbound message for the region.
func recordRateLimited(reg region.Region) { relayRateLimitedTotal.Inc(telemetry.Region(reg)) }

// recordReplied meters one reply-through message sent outbound for the region.
func recordReplied(reg region.Region) { relayRepliedTotal.Inc(telemetry.Region(reg)) }
