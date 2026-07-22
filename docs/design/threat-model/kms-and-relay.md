# Threat Model — KMS/HSM & Email Relay

> **DESIGN Appendix A.4–A.5** · [↑ DESIGN index](../../DESIGN.md) · prev: [hot-cold-paths](hot-cold-paths.md) · next: [residual-risks](residual-risks.md)

## KMS/HSM & signing keys — §4.4, §7.3

| STRIDE | Threat (concrete) | Mitigation |
|---|---|---|
| **S** | Impersonate the token signer | Signing **private keys never leave the HSM boundary** (§7.3); public half only in JWKS. |
| **T** | Unauthorized key use or rotation | **HSM access control**, **audited key operations**, **rotation-with-overlap** so rotations are controlled and reversible (§7.3). |
| **R** | Dispute over who used/rotated a key | **All key operations are audited** (§7.3). |
| **I** | Key extraction; per-user **DEK** exposure; **bulk decrypt** | **Envelope encryption** (per-user DEK wrapped by regional KEK, §4.4); **no bulk-decrypt capability** (§2.3); **per-region KEK** contains blast radius. |
| **D** | Signing throughput limits; KMS outage | Public **JWKS cached at the edge** so **verification survives KMS blips** (§6.1); capacity planning; verify path never calls the HSM. |
| **E** | Insider uses keys to **deanonymize** users | **Per-user pairwise secret** (no global secret, §3.2); **no bulk decrypt**; least privilege + audit + **separation of duties** (§2.3). |

## Email relay — §7.5

| STRIDE | Threat (concrete) | Mitigation |
|---|---|---|
| **S** | Spoofed sender to a relay address; phishing *via* the relay | **SPF/DKIM/DMARC alignment** authenticates the sender domain (§7.5.2). *Caveat:* a relay address accepts mail from **any authenticated sender**, not only the paired RP — so we lean on rate-limits + kill switches, not sender allow-listing (§7.5.2). |
| **T** | Message altered in transit on forward | **ARC sealing** on forward so downstream inboxes still trust the relayed message (§7.5.2). |
| **R** | Dispute over whether mail was delivered | **Accepted trade-off (privacy over non-repudiation):** we keep only minimal routing metadata and **retain no message content** (§7.5.2), so we deliberately *cannot* prove delivery of a message's contents — consistent with the no-tracking promise (§2.2). |
| **I** | Real-email leak; **relay→user** linkage | **Opaque, unlinkable** relay addresses (§7.5.1); **encrypted, region-local mapping** table; **no content retention** (§7.5.2, §7.5.5). |
| **D** | Mail-bomb a relay address | **Per-address rate limits** (§7.5.6) + instant **hard-bounce kill switch** (§7.5.4). |
| **E** | Abuse relay as an **open relay / spam amplifier** | **Inbound-only forwarding** — no arbitrary outbound send; reply-through is gated and phase-2 (§7.5.2). |
