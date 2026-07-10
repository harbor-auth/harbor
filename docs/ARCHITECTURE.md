# Harbor — Architecture at a Glance

> A one-page, high-level map of the **open-source Harbor core**. This is the
> friendly on-ramp; [`DESIGN.md`](DESIGN.md) is the authoritative deep dive
> (the `§` references below point into it).

Harbor is an **OpenID Provider (OP)** built on three pillars — *verifiable
privacy*, *data sovereignty*, and *extreme performance* (§0). The whole system
falls out of one guiding split: a **stateless HOT path** that verifies/issues
tokens at the edge, and a **stateful COLD path** for everything slower — each
per-region, so a user's data never leaves their jurisdiction.

## The 10,000-ft view

```
              ┌─────────────────────── GLOBAL (PII-FREE) ───────────────────────┐
              │   RP registry metadata  ·  region resolver  ·  status/billing    │
              │   no user data · no keys — a breach here leaks nothing sensitive  │  §5.3
              └───────────────────────────────┬──────────────────────────────────┘
                                               │ region prefix in id/issuer
                                               │ routes with NO global lookup   §5.1
  ============================================ ▼ ============ trust boundary ====
                        ┌──────────────── REGION: eu.harbor.id ─────────────────┐
   RP / Browser ──────► │                    EDGE (per region)                  │
                        │   Anycast · TLS · CDN cache: /jwks.json /.well-known   │  §4.1
                        └───────────┬───────────────────────────┬───────────────┘
                                    │                           │
                       HOT (stateless, cacheable)     COLD (stateful)
                                    │                           │
                    ┌───────────────▼──────────┐   ┌────────────▼───────────────┐
                    │      harbor-hot          │   │      harbor-mgmt           │
                    │  /authorize  /token      │   │  dashboard / BFF           │
                    │  /jwks  discovery        │   │  RP registration · consent │  §8.2
                    │  verify / introspect  ⚡ │   │  passkey/MFA enroll · audit│
                    └───────────────┬──────────┘   └────────────┬───────────────┘
                                    │                           │
                    ┌───────────────▼───────────────────────────▼───────────────┐
                    │         Regional data plane (this jurisdiction ONLY)        │
                    │   Postgres (primary + replicas)  ·  Redis                   │  §4.1
                    │   Regional KMS/HSM 🔑 (per-region KEKs + signing keys)       │  §4.4
                    └─────────────────────────────────────────────────────────────┘
```

## Why it's shaped this way

| Piece | What it does | Why it matters | Design |
|---|---|---|---|
| **HOT path** (`harbor-hot`) | Issues & verifies asymmetric-signed JWTs | Verification is an **offline JWKS signature check** — no DB, no callback — so RPs verify themselves and we serve millions/sec cheaply | §3.3, §6.1 |
| **COLD path** (`harbor-mgmt`) | Dashboard, RP registration, consent, passkey/MFA enrollment, audit | Slower, stateful, scales **independently** from the hot path | §4.1, §6.2 |
| **Regional data plane** | Postgres + Redis + KMS/HSM, per jurisdiction | **Data sovereignty**: PII (and the keys to it) never leave the region | §5, §4.4 |
| **Global control plane** | RP registry metadata + region resolver | Deliberately **PII-free**: routes on the region prefix alone, so it holds nothing worth stealing | §5.3 |
| **PPID** | A different `sub` per RP, keyed by a per-user secret | RPs **can't correlate** a user across apps — and neither can we, casually | §3.2 |

## The two things that make Harbor different

1. **You verify tokens without asking us.** ID/access tokens are JWTs signed
   with a regional key; the RP fetches `/jwks.json` once, caches it, and checks
   signatures locally forever after. That offline check *is* the performance
   story (§6.1) — and it's why revocation is handled by short TTLs + opaque
   refresh tokens rather than a per-request lookup (§3.5).
2. **The region is in the identifier.** `eu.harbor.id` (or an `eu_…` handle)
   tells the edge exactly which jurisdiction owns the request — routing is a
   pure string operation, no global database (§5.1). A bad rollout or a legal
   request is contained to one region.

## Where to go next

- **The full design** — [`DESIGN.md`](DESIGN.md): trust model (§2), protocol &
  tokens (§3), routing (§5), performance (§6), security (§7), data model (§10),
  the full OIDC login walkthrough (§11.2), and the STRIDE threat model
  (Appendix A).
- **As-built features** — [`docs/README.md`](README.md): the feature/plan index
  (PPID, passkeys, OIDC authorization-code, and the agentic foundations).
- **Proprietary side** — the SaaS control plane, billing, and production infra
  live in the closed-source [`harbor-auth/harbor-cloud`](https://github.com/harbor-auth/harbor-cloud)
  repo, which consumes this core **only** as OCI images + the Apache-2.0 `api/`
  contracts (see the *Proprietary components* note in
  [`../README.md`](../README.md#license), and `harbor-cloud`'s own
  `docs/ARCHITECTURE.md` for the reverse view).
