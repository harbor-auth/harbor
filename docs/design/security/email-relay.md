> **DESIGN §7.5** · [↑ DESIGN index](../../DESIGN.md) · prev: [overview](overview.md)

# Per-RP Email Relay (Hide-My-Email)

A core privacy feature borrowed from Apple (§2.4.2) and offered on the consent screen (§11.2, step 3): each RP gets a **unique, per-app random relay address** that forwards to the user's real inbox, so the user's **real email is never shared by default**. Apps can email the user; they never learn the user's real address, cannot use it as a cross-app identifier, and can be **cut off individually**.

## 7.5.1 Address generation

- Format: `<opaque-token>@relay.<region>.harbor.id` (e.g. `x7f3q9a2@relay.eu.harbor.id`). The subdomain is **region-scoped** so inbound routing and data residency stay consistent with §5.
- The `<opaque-token>` is **randomly generated and unlinkable** — it is **not** derived from the user id in any way an RP could reverse or correlate. Two RPs' relay addresses for the same user look completely unrelated.
- **One relay address per `(user, RP)` grant.** A mapping row `relay_address → user → client_id` is stored **encrypted at rest** in the user's **home region** (never replicated cross-region, per §5).
- Because the address embeds only the region (not the user), the mapping table is the *only* thing that links a relay address back to a person — and it lives behind the same regional encryption as the rest of the user's PII.

## 7.5.2 Forwarding infrastructure

Inbound MX for `relay.<region>.harbor.id` points at a **regional inbound mail service** that, per message:

1. **Looks up** the relay mapping (`relay_address → user + client_id`); unknown address ⇒ reject.
2. **Checks the address is active** and authenticates the sending domain via **SPF / DKIM / DMARC alignment** (anti-spoofing). Note this authenticates *who sent it*, not *that it's the paired RP*: a relay address accepts mail from **any authenticated sender**, so we lean on rate-limiting and per-address kill switches (§7.5.4, §7.5.6) — not sender allow-listing — to contain abuse.
3. **Rewrites and forwards** the message to the user's real address, **ARC-sealing** on forward so downstream inboxes still trust it after we've relayed it.
4. **(Phase 2) Reply-through:** outbound rewrite so a user can *reply* to the app without leaking their real address — the reply egresses from the relay address.

Operational notes:

- **We become a forwarder**, so deliverability is a first-class concern: correct SPF/DKIM for our relay domains, **ARC sealing**, per-address **rate limits**, and edge **spam filtering**.
- **No content retention / no tracking:** we keep only minimal routing metadata needed to forward and rate-limit; **message bodies are never logged or stored** (consistent with the no-tracking promise, §2.1–§2.2).

## 7.5.3 Bring-your-own-domain (BYO-domain)

Advanced users can point **their own domain** (or a subdomain) at Harbor, so relay addresses become e.g. `x7f3q9a2@mail.alice.example`:

- Delivers **vanity + provider-independence** (the user isn't tied to `harbor.id` for their masked mail).
- Requires **DNS verification** (a TXT challenge) plus **MX / SPF / DKIM** setup; Harbor publishes the exact records to add.
- The domain is still **region-pinned** — inbound processing happens in the user's home region regardless of the vanity domain.

## 7.5.4 Per-app deactivation (the email kill switch)

- The dashboard lets the user **deactivate any relay address** independently. Deactivated ⇒ inbound mail is refused with a **hard bounce** (recommended over silent-drop, so legitimate senders learn the address is gone rather than silently losing mail).
- This is an **instant, per-app email kill switch**: leaked/spammy app ⇒ kill its address; every other app is unaffected.
- **Independent of the RP grant:** deactivating the relay does **not** revoke the login, and revoking the login (§11.3) does not by itself require killing the relay — the user can cut email while keeping access, or vice versa.

## 7.5.5 Data-sovereignty consistency

- The relay **mapping table and all inbound mail processing live entirely in the user's home region**; the MX subdomain is **region-scoped** (`relay.<region>.harbor.id`).
- **No cross-region replication** of relay mappings or mail contents — mail for an `eu` user is only ever processed in EU. Ties directly back to §5.

## 7.5.6 Abuse & privacy safeguards

- **Per-address rate limiting** to contain spam/abuse without per-user behavioral logging.
- Users can see **aggregate-only** per-RP volume ("App X sent you 12 emails this week") — never message contents or sender-level tracking.
- **(Optional) tracking-pixel stripping** on forward, to blunt open-tracking by senders.
- **No content retention** — nothing beyond ephemeral routing/rate-limit state.

## 7.5.7 Relay states

| State | Inbound behavior | Notes |
|---|---|---|
| **Active** | Forwarded to the user's real inbox (after SPF/DKIM/DMARC checks, ARC-sealed) | Default on first consent; one address per (user, RP). |
| **Deactivated** | **Hard bounce** (address refused) | Instant per-app kill switch; independent of the RP login grant. |
| **BYO-domain** | Forwarded via the user's own verified domain (`x@mail.alice.example`) | Region-pinned; requires DNS/MX/SPF/DKIM verification. |
