# Threat Model — Components & Trust Boundaries

> **DESIGN Appendix A.1** · [↑ DESIGN index](../../DESIGN.md) · next: [hot-cold-paths](hot-cold-paths.md)

This appendix expands the high-level threat model in §2.3 with a **per-component STRIDE analysis**. §2.3 is the summary (adversary-oriented); this appendix is the detailed, component-oriented expansion. Most mitigations already exist elsewhere in the design — this appendix *maps* them to concrete threats rather than inventing new controls.

**STRIDE legend:** **S**poofing (identity) · **T**ampering (integrity) · **R**epudiation (deniability) · **I**nformation disclosure (confidentiality) · **D**enial of service (availability) · **E**levation of privilege (authorization).

We analyze each trust-boundary component separately because their risk profiles differ sharply: the hot path is a stateless, internet-facing verification surface; the KMS is a small, extremely-high-value secret store; the relay is an inbound-mail surface; and so on.

## Components & trust boundaries

| # | Component | What it is | Design refs |
|---|---|---|---|
| (a) | **Hot path** (`harbor-hot`) | `/authorize`, `/token`, `/jwks`, discovery, verify/introspect — stateless, internet-facing | §4.1, §6.1 |
| (b) | **Cold path / management plane** | Dashboard/BFF, enrollment, consent, audit, admin | §4.1, §6.2 |
| (c) | **KMS/HSM & signing keys** | Per-region KEKs + token-signing keys; per-user DEKs | §4.4, §7.3 |
| (d) | **Email relay** | Inbound MX + forwarding for `relay.<region>.harbor.id` | §7.5 |
| (e) | **Global control plane** | PII-free RP registry + region resolver | §5.3 |

```
            ┌── (e) GLOBAL control plane (PII-FREE) ──┐
            │   RP registry · region resolver         │  no keys, no user data
            └───────────────┬─────────────────────────┘
   ==============  trust boundary: nothing sensitive crosses  ==============
            ┌───────────────▼──────────── REGION (jurisdiction) ───────────┐
   internet │  (a) HOT path ⚡         (b) COLD path 🔒                     │
   ────────►│  authorize/token/jwks    dashboard/consent/admin             │
            │        │                      │                             │
            │        └──────┬───────────────┘                             │
            │        (c) KMS/HSM 🔑    (d) Email relay ✉ (inbound MX)      │
            │        per-region keys   opaque→real forwarding             │
            └──────────────────────────────────────────────────────────────┘
```
