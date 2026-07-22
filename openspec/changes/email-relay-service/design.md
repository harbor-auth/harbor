# Design: Email relay service (per-RP Hide-My-Email)

## Key Decisions

### Decision 1: Opaque, unlinkable relay tokens (not user-id-derived)
**Chosen:** Generate the `<opaque-token>` randomly; it is **not** derived from
the user id in any way an RP could reverse or correlate. One address per
`(user, RP)` grant.
**Rationale:** The entire point of Hide-My-Email is to deny cross-app
correlation. If the token were a hash of the user id (even keyed), a leak of the
keying scheme — or a collusion analysis across RPs — could re-link addresses to
one user. A random token means the mapping table is the *only* link, and it
lives behind regional envelope crypto.
**Alternatives considered:** HMAC(user_id, rp) tokens (rejected — deterministic
linkage risk if the key leaks); sequential ids (rejected — trivially
enumerable/correlatable).

### Decision 2: Region-pinned, envelope-encrypted mapping, never cross-region
**Chosen:** Store `relay_address → user → client_id` envelope-encrypted at rest
in the user's home region; never replicate it cross-region. Inbound processing
for an `eu` user happens only in EU.
**Rationale:** The mapping is the one artefact that de-masks a relay address to a
person — it is maximally sensitive PII and must obey §5 residency exactly like
the rest of the user's data. Replication would create a cross-region de-masking
copy.
**Alternatives considered:** A global mapping table for routing convenience
(rejected — a cross-region PII index, a direct §5 violation); plaintext mapping
(rejected — a DB leak de-masks every address).

### Decision 3: BUILD Go-native (go-smtp + go-msgauth, MIT), don't buy
**Chosen:** A minimal Go-native inbound forwarder on `emersion/go-smtp` +
`emersion/go-msgauth` (both MIT), embedded region-pinned in Harbor.
**Rationale:** SimpleLogin/addy.io are AGPL-3.0 (copyleft) and Python/PHP stack
mismatches; Firefox Relay is Mozilla/AWS-coupled; managed inbound APIs
(SES/Postmark/Mailgun) process message content — user PII — in vendor infra,
violating the strict no-external-SaaS-callout residency rule. MIT Go libraries
keep the inbound PII path entirely on our own regional infrastructure.
**Alternatives considered:** SimpleLogin/addy.io self-host (rejected — AGPL +
second runtime); SES inbound (rejected — PII in vendor infra); Postfix + custom
milter (rejected — heavier ops surface than an embeddable Go SMTP server for our
narrow forwarding need).

### Decision 4: Hard-bounce kill switch, independent of the login grant
**Chosen:** Deactivating a relay address refuses inbound mail with a **hard
bounce**, and this is **independent** of the RP login grant — killing email does
not revoke login, and revoking login does not by itself kill the relay.
**Rationale:** Users need to cut a spammy app's email while keeping (or
separately revoking) its login. A hard bounce (over a silent drop) tells
legitimate senders the address is gone instead of silently losing their mail.
**Alternatives considered:** Silent drop on deactivation (rejected — legitimate
senders lose mail with no signal); chaining email-kill to login-revoke (rejected
— conflates two independent user controls, §7.5.4).

### Decision 5: No content retention
**Chosen:** Message bodies are never logged or stored; only minimal ephemeral
routing/rate-limit state is kept.
**Rationale:** Retaining bodies would recreate the surveillance capability Harbor
denies (§2.1–§2.2) and enlarge the breach blast radius. Forwarding needs the
body only transiently.
**Alternatives considered:** Store bodies for debugging/replay (rejected — a
standing PII store and a tracking vector); log headers with addresses (rejected —
headers carry PII and the relay linkage).

## Interface sketch

```go
package relay

// Mint returns the opaque, unlinkable relay address for a (user, client) grant,
// creating it (region-pinned, envelope-encrypted) on first use.
func Mint(ctx context.Context, userID UserID, clientID ClientID) (Address, error)

// Resolve looks up an inbound relay address to its (user, client) mapping in the
// pinned region; unknown or deactivated addresses return an error (reject/bounce).
func Resolve(ctx context.Context, addr Address) (Mapping, error)

// Deactivate flips an address to Deactivated (inbound => hard bounce). It does
// NOT touch the RP login grant.
func Deactivate(ctx context.Context, userID UserID, addr Address) error
```

## Security & privacy invariants

- Relay tokens are unlinkable — not user-id-derived; two RPs' addresses for one
  user are uncorrelated (Decision 1).
- The mapping is envelope-encrypted, region-pinned, and never replicated
  cross-region (Decision 2).
- Inbound mail is authenticated (SPF/DKIM/DMARC), ARC-sealed on forward, and its
  body is never logged or stored (Decision 5).
- A deactivated address hard-bounces; the kill switch is independent of the
  login grant (Decision 4).
- No external SaaS is on the inbound PII path (Decision 3).
