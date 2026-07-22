# Proposal: Email relay service (per-RP Hide-My-Email)

## Problem

Harbor's consent screen promises **Hide-My-Email** (§7.5): each RP gets a
**unique, per-app, random relay address** forwarding to the user's real inbox,
so the real address is **never shared by default**, cannot become a cross-app
identifier, and can be **cut off individually**. None of it exists — no mapping
store, no inbound mail service, no kill switch. Without it, any RP that emails
the user learns the user's real address, recreating exactly the cross-app
tracking identifier Harbor exists to prevent.

## Proposed Solution

1. **Opaque, unlinkable addresses** — mint one
   `<opaque-token>@relay.<region>.harbor.id` per `(user, RP)` grant; the token
   is **randomly generated and unlinkable** — not derived from the user id in
   any RP-reversible way — so two RPs' addresses for one user are uncorrelated.
2. **Region-pinned, encrypted mapping** — store the `relay_address → user →
   client_id` row **envelope-encrypted at rest** in the user's **home region**,
   **never** cross-region replicated (§5). The mapping table is the only link
   from address to person.
3. **Go-native inbound MTA** — a regional inbound mail service on
   **`emersion/go-smtp`** + **`emersion/go-msgauth`** (both MIT) looks up the
   mapping (unknown ⇒ reject), authenticates the sender via **SPF/DKIM/DMARC**
   alignment, **ARC-seals**, and forwards to the real inbox with **no content
   retention** (bodies never logged or stored).
4. **Hard-bounce kill switch** — deactivating an address is an instant per-app
   kill switch (inbound ⇒ **hard bounce**), **independent** of the RP login
   grant. Abuse is contained by **per-address rate limiting**; users see only
   **aggregate-only** per-RP volume.
5. **Phase 2** — reply-through outbound rewrite (reply without leaking the real
   address) and BYO-domain (region-pinned, DNS/MX/SPF/DKIM-verified).

## Non-Goals

- **No message content retention** — bodies are never stored or logged; only
  ephemeral routing/rate-limit state exists.
- **No external-SaaS callout on the inbound PII path** — no SES/Postmark/Mailgun
  inbound; a region-pinned managed *outbound* sender is a later, opt-in add-on
  only.
- **No sender allow-listing** — a relay address accepts mail from any
  *authenticated* sender; containment is rate limits + kill switch, not
  allow-lists.
- **No cross-region replication** of relay mappings or mail — an `eu` user's
  mail is processed only in EU.

## Success Criteria

- [ ] One opaque, **unlinkable** relay address per `(user, RP)` grant; two RPs' addresses for one user are uncorrelated.
- [ ] The `relay_address → user → client_id` mapping is envelope-encrypted at rest, region-pinned, and never replicated cross-region.
- [ ] The inbound MTA rejects unknown addresses, enforces SPF/DKIM/DMARC alignment, ARC-seals, and forwards — with **no** body retention.
- [ ] A **deactivated** address **hard-bounces**; the kill switch is **independent** of the RP login grant (and vice versa).
- [ ] Per-address rate limiting contains abuse; per-RP volume is aggregate-only.
- [ ] Inbound processing uses no external-SaaS callout (Go-native `go-smtp`/`go-msgauth`).
- [ ] `make agent-check` clean.
