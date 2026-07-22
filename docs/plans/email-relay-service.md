---
title: Email relay service (per-RP Hide-My-Email — masked addresses & forwarding)
status: draft
design_refs: [§7.5, §5, §11.2]
targets: [db/migrations/, internal/relay/, internal/mgmtapi/, cmd/harbor-hot/]
promoted_to: null
openspec: changes/email-relay-service
created: 2026-07-22
---

# Email relay service (plan)

> **Dependency order:** **Gate 4** of Wave 5 — the last gate. Depends on the
> shipped `consent-ledger` ✅ (per-(user, RP) grant taxonomy — a relay address is
> minted against a grant) and `client-grant-persistence` ✅ (the persisted
> client/grant a relay maps to). Its per-RP toggle is **soft-surfaced** by
> `consent-management-ui` (feature-detected — the dashboard degrades gracefully
> if relay isn't live). Inherits the **Gate-1 guardrails**: every mapping read is
> region-pinned (`regional-data-residency-routing`) and every counter is
> aggregate-only (`observability-metrics`). Reserves migration prefix **`0016`**.
> This is a **single full-scope** plan: the implementation checklist sequences
> the **data/control plane first** (mapping, lifecycle, kill-switch, DNS
> scaffolding) and the **inbound mail plane second** (regional MTA, SPF/DKIM/
> DMARC, ARC-seal, forward), then Phase 2 (reply-through + BYO-domain).

## Problem

Harbor's consent screen promises **Hide-My-Email** (§7.5, §2.4.2): each RP gets a
**unique, per-app, random relay address** that forwards to the user's real
inbox, so the user's **real email is never shared by default**. Apps can email
the user; they never learn the real address, cannot use it as a cross-app
identifier, and can be **cut off individually**. None of this exists yet: there
is no relay mapping store, no inbound mail service, and no per-app kill switch.
Without it, every RP that needs to email the user gets the user's real address —
directly recreating the cross-app tracking identifier Harbor exists to prevent.

## Build vs buy

**Verdict: BUILD (Go-native), do not buy.**

- **SimpleLogin** (`simple-login/app`) and **addy.io / AnonAddy**
  (`anonaddy/anonaddy`) are **AGPL-3.0** — a copyleft-contamination risk for a
  linked service — and are **stack mismatches** (Python / PHP) that would import
  a second runtime and ops surface.
- **Mozilla Firefox Relay** (`mozilla/fx-private-relay`) is tightly coupled to
  **Mozilla accounts + AWS SES**; it is not practically self-hostable standalone
  and drags in vendor coupling.
- **Managed inbound APIs** (AWS SES inbound, Postmark, Mailgun routes) process
  message content — user PII — in **vendor infrastructure**, which violates
  Harbor's strict **no-external-SaaS-callout** data-sovereignty rule (§5): a
  user's mail for an `eu` user must be processed only in EU, on our own
  infrastructure.
- **Chosen stack:** a minimal Go-native inbound forwarder built on
  **`emersion/go-smtp`** (inbound SMTP server) and **`emersion/go-msgauth`**
  (DKIM / ARC / DMARC helpers) — **both MIT-licensed**, pure-Go, and embeddable
  directly in a region-pinned Harbor mail service with no external callout.
  Outbound relay egresses through a **self-run regional SMTP relay**; a
  region-pinned managed *outbound* sender may be added later behind an explicit
  opt-in flag, but is never on the inbound PII path.

## Proposed approach

Build the relay as two internally-sequenced planes in one feature.

1. **Data / control plane (first).**
   - **Address generation (§7.5.1)** — mint one `<opaque-token>@relay.<region>.harbor.id`
     per `(user, RP)` grant. The token is **randomly generated and unlinkable** —
     **not** derived from the user id in any RP-reversible way; two RPs' relay
     addresses for the same user look completely unrelated.
   - **Mapping store (`0016_relay_addresses`)** — a `relay_address → user →
     client_id` row **envelope-encrypted at rest** in the user's **home region**,
     **never** cross-region replicated (§5). The mapping table is the only link
     from a relay address back to a person and lives behind the same regional
     crypto as the rest of the user's PII.
   - **Lifecycle + kill switch (§7.5.4, §7.5.7)** — relay states
     **Active / Deactivated / BYO-domain**; deactivation is an **instant per-app
     kill switch** (inbound → **hard bounce**), **independent of the RP login
     grant** (killing email does not revoke login; revoking login does not by
     itself kill the relay).
   - **Region DNS scaffolding** — the region-scoped MX subdomain
     `relay.<region>.harbor.id` and SPF/DKIM records for our relay domains
     (records only; live inbound wiring is the mail plane).
2. **Inbound mail plane (second).** A **regional inbound MTA** on `go-smtp` that,
   per message (§7.5.2): looks up the mapping (unknown ⇒ reject); checks the
   address is **Active** and authenticates the sending domain via **SPF / DKIM /
   DMARC alignment**; **ARC-seals** and **forwards** to the user's real inbox.
   **No content retention** — message bodies are never logged or stored; only
   minimal ephemeral routing/rate-limit state is kept (§7.5.6). **Per-address
   rate limiting** contains abuse without per-user behavioural logging; users see
   **aggregate-only** per-RP volume.
3. **Phase 2 (last, in the same checklist).** **Reply-through** outbound rewrite
   (a user replies to the app without leaking their real address — egress from
   the relay address) and **BYO-domain** (§7.5.3): a user points their own
   verified, still-region-pinned domain at Harbor via a TXT challenge + MX/SPF/
   DKIM setup.

## DESIGN alignment

Realises §7.5 (per-RP email relay) end-to-end and keeps §5 (region-pinned
mapping + inbound processing, no cross-region replication) and §11.2 (relay is a
consent-screen privacy control). Does **not** change `DESIGN.md` — §7.5 already
specifies address generation, forwarding, deactivation, data-sovereignty, and
the relay states; this plan builds the missing service.

## Target code paths

- `db/migrations/0016_relay_addresses.up.sql` / `.down.sql` — `relay_addresses`
  (`relay_token`, `user_id`, `client_id`, `state`, `enc_mapping`, `region`,
  `created_at`, `deactivated_at`).
- `db/queries/relay_addresses.sql` — mint (one per `(user, client)`), lookup by
  token (region-pinned), deactivate, list-for-user.
- `internal/relay/address.go` — opaque unlinkable token generation; the
  `(user, RP)` uniqueness rule; state lifecycle.
- `internal/relay/store.go` — envelope-encrypted, region-pinned mapping store
  (reuses `internal/crypto/` + the region seam).
- `internal/relay/mta.go` — `go-smtp` inbound handler: lookup → SPF/DKIM/DMARC
  (`go-msgauth`) → ARC-seal → forward; no body retention; per-address rate
  limit.
- `internal/mgmtapi/relay.go` — user endpoints: list relay addresses, deactivate
  (kill switch), BYO-domain verify (Phase 2).
- `cmd/harbor-hot/main.go` — wire the relay lookup/mint seam behind the consent
  grant path (single call-site).

## Implementation checklist

_Data / control plane first:_

- [ ] Migration `0016_relay_addresses` (up/down): `relay_addresses(relay_token, user_id, client_id, state, enc_mapping, region, created_at, deactivated_at)`; unique `(user_id, client_id)`; index on `relay_token`.
- [ ] `db/queries/relay_addresses.sql` + `make codegen`: mint-one-per-(user, client), region-pinned lookup-by-token, deactivate, list-for-user.
- [ ] Opaque **unlinkable** token generation (random; **not** derived from `user_id` in any RP-reversible way); two RPs' addresses for one user are uncorrelated.
- [ ] Envelope-encrypted, **region-pinned** mapping store (reuse `internal/crypto/` + region seam); mapping **never** replicated cross-region.
- [ ] Relay state lifecycle (`Active` / `Deactivated` / `BYO-domain`).
- [ ] Per-app **hard-bounce kill switch** on `Deactivated`, **independent** of the RP login grant (email off ≠ login revoked, and vice versa).
- [x] Region DNS scaffolding: `relay.<region>.harbor.id` MX subdomain + SPF/DKIM records for the relay domains (records only). See [email-relay-dns.md](email-relay-dns.md) for operational reference.
- [ ] `internal/mgmtapi/relay.go`: list addresses + deactivate; aggregate-only per-RP volume view.
- [ ] Wire the mint/lookup seam behind the consent grant path in `cmd/harbor-hot/main.go` (single call-site).

_Inbound mail plane second:_

- [ ] `internal/relay/mta.go` on **`emersion/go-smtp`**: inbound handler that looks up the mapping (unknown ⇒ reject) and checks the address is `Active`.
- [ ] SPF / DKIM / DMARC **alignment** check via **`emersion/go-msgauth`** (authenticate the sender; reject on failure).
- [ ] **ARC-seal** on forward and forward to the user's real inbox; correct SPF/DKIM for our relay domains so forwarded mail stays deliverable.
- [ ] **No content retention**: message bodies are never logged or stored; keep only ephemeral routing/rate-limit state.
- [ ] **Per-address rate limiting** (contain abuse without per-user behavioural logging); meter aggregate-only `accept`/`bounce`/`forward` counts via `observability-metrics`.

_Phase 2:_

- [ ] **Reply-through** outbound rewrite: a user reply egresses from the relay address, never leaking the real address.
- [ ] **BYO-domain** (§7.5.3): TXT-challenge DNS verification + MX/SPF/DKIM setup; the vanity domain stays **region-pinned**.
- [ ] Tests: address is unlinkable (not user-id-derived); mapping is region-pinned and not readable cross-region; unknown address is rejected; SPF/DKIM/DMARC-failing mail is rejected; forwarded mail is ARC-sealed; **no** body is logged/stored; deactivated address **hard-bounces**; deactivation does **not** revoke login (and login-revoke does not deactivate); per-RP volume is aggregate-only.
- [ ] Tests (privacy): the relay mapping is the only user link and stays behind regional envelope crypto; two RPs' addresses for one user are uncorrelated.
- [ ] Author & verify paired OpenSpec change: `openspec validate email-relay-service --strict`
- [ ] Reconcile & promote: `@plan promote email-relay-service`

## Risks & open questions

- **We become a forwarder — deliverability is first-class.** Forwarding breaks
  naive SPF; mitigate with correct SPF/DKIM for our relay domains and **ARC
  sealing** so downstream inboxes still trust relayed mail. Monitor bounce rates
  (aggregate-only) and warm the relay domains.
- **ARC sealing correctness** — a broken ARC seal silently tanks deliverability.
  Use `go-msgauth`'s ARC support and freeze test vectors for the seal.
- **Abuse without per-user logging** — a relay address accepts mail from **any**
  authenticated sender (we authenticate *who sent it*, not *that it's the paired
  RP*), so containment leans on **per-address rate limits** and the **kill
  switch**, never on per-user behavioural logs or sender allow-listing.
- **Hard-bounce vs silent-drop** — deactivated addresses **hard-bounce**
  (recommended by §7.5.4) so legitimate senders learn the address is gone rather
  than silently losing mail; document the trade-off.
- **No content retention** — bodies are never persisted or logged; only ephemeral
  routing/rate-limit state exists. Any future feature that wants message content
  is a design change, not an implementation detail.
- **Kill-switch independence** — deactivation and login-revocation are
  deliberately decoupled (§7.5.4); the two lifecycles must not be accidentally
  chained.

## Definition of done

`go build/vet/test ./...` green; each `(user, RP)` grant has one opaque,
unlinkable, region-pinned, envelope-encrypted relay address; the regional
inbound MTA looks up the mapping, enforces SPF/DKIM/DMARC, ARC-seals, and
forwards with **no** body retention; a deactivated address hard-bounces as an
instant per-app kill switch independent of the login grant; per-RP volume is
aggregate-only; reply-through and BYO-domain (region-pinned) work; no external
SaaS is on the inbound PII path; `make agent-check` clean. Ready to `@plan
promote`.
