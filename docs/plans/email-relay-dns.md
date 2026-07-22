---
title: Email relay DNS scaffolding
status: draft
design_refs: [§7.5, §5]
parent: email-relay-service
created: 2026-07-22
---

# Email relay DNS scaffolding

> **Operational reference** for the `relay.<region>.harbor.id` DNS structure.
> This document covers the MX subdomain layout, SPF/DKIM/DMARC record
> requirements, and region-scoped routing for the per-RP email relay service
> (§7.5). See [email-relay-service.md](email-relay-service.md) for the full
> feature plan.

## Overview

Harbor's Hide-My-Email relay addresses follow the format:

```
<opaque-token>@relay.<region>.harbor.id
```

For example:
- `x7f3q9a2@relay.EU.harbor.id` — EU region
- `k9m2p5w1@relay.US.harbor.id` — US region
- `j4n8r6t3@relay.APAC.harbor.id` — APAC region

> **Note:** DNS is case-insensitive, so `relay.EU.harbor.id` and `relay.eu.harbor.id`
> resolve identically. The examples below use lowercase for DNS records (convention)
> but the actual email addresses use uppercase region codes as emitted by `FormatEmail`.

The **region-scoped subdomain** (`relay.<region>`) ensures:
1. Inbound mail routes to the correct regional MTA (data sovereignty, §5)
2. All processing for a user's relay address stays in their home region
3. No cross-region DNS or mail routing lookups are required

---

## DNS zone structure

### Per-region MX subdomains

Each supported region requires its own `relay.<region>.harbor.id` subdomain with
dedicated MX records pointing to the regional inbound MTA cluster.

| Region | Subdomain | MX target |
|--------|-----------|-----------|
| EU | `relay.eu.harbor.id` | `mta-eu.harbor.id` |
| US | `relay.us.harbor.id` | `mta-us.harbor.id` |
| APAC | `relay.apac.harbor.id` | `mta-apac.harbor.id` |

**Example DNS records (EU region):**

```dns
; MX record — inbound mail routing
relay.eu.harbor.id.    IN MX 10 mta-eu.harbor.id.

; A/AAAA records for the MTA cluster (example IPs)
mta-eu.harbor.id.      IN A     203.0.113.10
mta-eu.harbor.id.      IN AAAA  2001:db8::10
```

### MTA cluster considerations

- **Multiple MX priorities** for failover (e.g., `MX 10`, `MX 20`) if running
  multiple MTA instances per region.
- **Geographic proximity** — MTA instances should be deployed in the same
  region as the database holding the relay mappings (no cross-region DB calls).
- **Load balancing** — use DNS round-robin or external load balancers for
  horizontal scaling within a region.

---

## SPF records

SPF (Sender Policy Framework) authorises which hosts may send mail **from** the
relay domains. This is critical for deliverability when forwarding mail to
users' real inboxes.

### Per-region SPF records

Each `relay.<region>.harbor.id` subdomain needs its own SPF record listing the
regional MTA IPs/hostnames that will send outbound (forwarded) mail.

**Example (EU region):**

```dns
relay.eu.harbor.id.    IN TXT "v=spf1 a:mta-eu.harbor.id ~all"
```

**Expanded example with explicit IPs:**

```dns
relay.eu.harbor.id.    IN TXT "v=spf1 ip4:203.0.113.10 ip6:2001:db8::10 ~all"
```

### SPF alignment notes

- Use `~all` (softfail) initially for monitoring; tighten to `-all` (hardfail)
  once confident in the setup.
- **Include** any additional sending infrastructure (e.g., backup MTAs,
  outbound-only relays) in the SPF record.
- Keep the SPF record **under 10 DNS lookups** (SPF lookup limit).

---

## DKIM records

DKIM (DomainKeys Identified Mail) cryptographically signs outbound mail so
receiving servers can verify the message wasn't tampered with and originated
from an authorised sender.

### DKIM key setup

Each region needs at least one DKIM signing key. Publish the **public key** in
DNS; the **private key** stays on the regional MTA.

**Selector naming convention:**

```
<purpose>-<region>-<key-rotation-id>._domainkey.relay.<region>.harbor.id
```

Example selectors:
- `relay-eu-2026q3._domainkey.relay.eu.harbor.id`
- `relay-us-2026q3._domainkey.relay.us.harbor.id`

**Example DKIM DNS record (EU region):**

```dns
relay-eu-2026q3._domainkey.relay.eu.harbor.id. IN TXT (
    "v=DKIM1; k=rsa; "
    "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
)
```

### DKIM operational notes

- **Key size:** minimum 2048-bit RSA (1024-bit is deprecated).
- **Key rotation:** rotate keys quarterly; publish the new key before switching
  the MTA to sign with it (overlap period).
- **Multiple selectors:** support parallel selectors for zero-downtime rotation.
- Use **`go-msgauth`** (`emersion/go-msgauth`) for DKIM signing in the Go MTA.

---

## DMARC records

DMARC (Domain-based Message Authentication, Reporting & Conformance) ties SPF
and DKIM together and tells receiving servers what to do with mail that fails
authentication.

### Per-region DMARC records

Each `relay.<region>.harbor.id` subdomain should have its own DMARC record.

**Example (EU region):**

```dns
_dmarc.relay.eu.harbor.id. IN TXT (
    "v=DMARC1; p=quarantine; "
    "rua=mailto:dmarc-reports-eu@harbor.id; "
    "ruf=mailto:dmarc-forensics-eu@harbor.id; "
    "adkim=r; aspf=r; pct=100"
)
```

### DMARC policy progression

| Phase | Policy | Purpose |
|-------|--------|---------|
| Initial | `p=none` | Monitor only; collect reports without affecting delivery |
| Hardening | `p=quarantine` | Suspicious mail goes to spam; catch misconfigurations |
| Production | `p=reject` | Unauthenticated mail is rejected outright |

### DMARC alignment

- `adkim=r` (relaxed) — DKIM domain can be a subdomain of the From domain.
- `aspf=r` (relaxed) — SPF domain can be a subdomain of the From domain.
- Consider `adkim=s` / `aspf=s` (strict) for tighter control once stable.

---

## ARC (Authenticated Received Chain) considerations

When Harbor **forwards** mail (from RP → relay address → user's real inbox),
the original SPF/DKIM checks may fail at the final destination because the
message now comes from Harbor's infrastructure, not the original sender.

**ARC sealing** preserves the original authentication results so downstream
servers can trust the forwarded message.

### ARC implementation notes

- Use **`go-msgauth`** for ARC sealing in the Go MTA.
- Sign ARC headers with the same DKIM key used for the relay domain.
- Include `ARC-Authentication-Results`, `ARC-Message-Signature`, and `ARC-Seal`
  headers on every forwarded message.

---

## BYO-domain DNS requirements

When a user brings their own domain (e.g., `mail.alice.example`), they must
configure:

1. **TXT verification record** — proves domain ownership:
   ```dns
   _harbor-verify.mail.alice.example. IN TXT "harbor-verify=<challenge-token>"
   ```

2. **MX record** — routes inbound mail to Harbor:
   ```dns
   mail.alice.example. IN MX 10 mta-<region>.harbor.id.
   ```

3. **SPF record** — authorises Harbor to send on behalf of the domain:
   ```dns
   mail.alice.example. IN TXT "v=spf1 include:relay.<region>.harbor.id ~all"
   ```

4. **DKIM record** — Harbor-managed DKIM key for the custom domain:
   ```dns
   harbor._domainkey.mail.alice.example. IN CNAME harbor._domainkey.relay.<region>.harbor.id.
   ```

5. **DMARC record** (recommended):
   ```dns
   _dmarc.mail.alice.example. IN TXT "v=DMARC1; p=quarantine; ..."
   ```

The BYO-domain remains **region-pinned** — all mail processing happens in the
user's home region regardless of the vanity domain.

---

## Operational checklist

### Initial setup (per region)

- [ ] Create `relay.<region>.harbor.id` subdomain in DNS
- [ ] Add MX records pointing to regional MTA cluster
- [ ] Generate DKIM keypair (2048-bit RSA minimum)
- [ ] Publish DKIM public key in DNS
- [ ] Add SPF record for the relay subdomain
- [ ] Add DMARC record (start with `p=none` for monitoring)
- [ ] Configure MTA to sign outbound mail with DKIM
- [ ] Configure MTA to add ARC headers on forward
- [ ] Test with mail-tester.com or similar tools
- [ ] Monitor DMARC reports for authentication failures

### Key rotation (quarterly)

- [ ] Generate new DKIM keypair with new selector
- [ ] Publish new public key in DNS (allow propagation time)
- [ ] Update MTA to sign with new key
- [ ] Keep old selector active for 7 days (in-flight mail)
- [ ] Remove old selector from DNS

### Monitoring

- [ ] DMARC aggregate reports (`rua`) — daily/weekly review
- [ ] DMARC forensic reports (`ruf`) — investigate failures
- [ ] Bounce rate monitoring (aggregate-only, per §6.5)
- [ ] SPF/DKIM/DMARC pass rates

---

## Region code mapping

The `internal/region` package defines the known regions:

| Constant | Value | Relay subdomain |
|----------|-------|-----------------|
| `region.EU` | `"EU"` | `relay.EU.harbor.id` |
| `region.US` | `"US"` | `relay.US.harbor.id` |
| `region.APAC` | `"APAC"` | `relay.APAC.harbor.id` |

When formatting a relay email address:

```go
// From internal/relay/address.go
func FormatEmail(token string, reg region.Region) string {
    return fmt.Sprintf("%s@relay.%s.harbor.id", token, reg)
}
```

Since `region.Region` constants are uppercase (`"EU"`, `"US"`, `"APAC"`), the
generated addresses use uppercase region codes (e.g., `token@relay.EU.harbor.id`).
DNS is case-insensitive, so the lowercase DNS records below work correctly.

---

## References

- [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208) — SPF
- [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376) — DKIM
- [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489) — DMARC
- [RFC 8617](https://www.rfc-editor.org/rfc/rfc8617) — ARC
- [emersion/go-msgauth](https://github.com/emersion/go-msgauth) — Go DKIM/ARC library
- [docs/DESIGN.md §7.5](../design/security/email-relay.md) — Per-RP email relay design
- [docs/DESIGN.md §5](../design/architecture/routing.md) — Regional data residency
