# Harbor — Privacy-First, Ethical SSO

> **Design Index (v0.1)** — a navigable map of the Harbor design.
> A privacy-preserving, tracking-free replacement for "Sign in with Google/Facebook".
> Core in Go, multi-jurisdiction, engineered for millions of verifications per second.

---

## TL;DR (§0)

Harbor is an **OpenID Provider (OP)** that lets people sign in to third-party apps ("Relying Parties" / RPs) **without being tracked**. Three pillars shape every decision:

1. **Verifiable privacy** — we technically constrain *ourselves* (the operator) from tracking users: no cross-RP correlation, minimal logging, pairwise pseudonymous identifiers (PPID), user-owned audit trail, open-source + third-party audited.
2. **Data sovereignty** — each user lives in exactly **one jurisdiction** (their home region). Their PII never leaves that region. Region is encoded in identifiers so requests route at the edge with **no global lookup**.
3. **Extreme performance & low cost** — the sign-in / token-verification hot path is **stateless and edge-cacheable** (asymmetric-signed tokens verified via JWKS, no DB hit), so we serve **millions of verifications/sec** cheaply.

A cross-cutting commitment shapes *how* we build: **standards-first, contract-first, codegen-everywhere** (§1).

---

## This design is a tree

Per the **small-files principle (§1.10)**, the design is split into focused files that each target one concern and stay under ~2,000 words. This file is the **spine**: start here, then follow the map below.

**Suggested reading order:** principles → product & trust → protocol → architecture → security → backend & data → flows → governance → threat model.

---

## § → file map

| § | File |
|---|---|
| §0 | This file |
| §1.1–1.6 | [design/principles/contracts-and-codegen.md](design/principles/contracts-and-codegen.md) |
| §1.7 | [design/principles/testing.md](design/principles/testing.md) |
| §1.8 | [design/principles/cicd.md](design/principles/cicd.md) |
| §1.9–1.10 | [design/principles/skills-and-small-files.md](design/principles/skills-and-small-files.md) |
| §2.1–2.3 | [design/product/trust-model.md](design/product/trust-model.md) |
| §2.4 | [design/product/privacy-positioning.md](design/product/privacy-positioning.md) |
| §3.2.1–3.2.3 | [design/protocol/ppid.md](design/protocol/ppid.md) |
| §3.2.4–3.2.7 | [design/protocol/ppid-guarantees.md](design/protocol/ppid-guarantees.md) |
| §3.1, §3.3–3.5 | [design/protocol/tokens.md](design/protocol/tokens.md) |
| §4 | [design/architecture/overview.md](design/architecture/overview.md) |
| §5 | [design/architecture/routing.md](design/architecture/routing.md) |
| §6.1–6.4 | [design/architecture/performance.md](design/architecture/performance.md) |
| §6.5 | [design/architecture/observability.md](design/architecture/observability.md) |
| §7.1–7.4 | [design/security/overview.md](design/security/overview.md) |
| §7.5 | [design/security/email-relay.md](design/security/email-relay.md) |
| §8–9 | [design/backend/stack.md](design/backend/stack.md) |
| §10 | [design/backend/data-model.md](design/backend/data-model.md) |
| §11.1, §11.3–11.6 | [design/flows/overview.md](design/flows/overview.md) |
| §11.2 | [OIDC-LOGIN-FLOW.md](OIDC-LOGIN-FLOW.md) |
| §11.7 | [design/flows/error-cases.md](design/flows/error-cases.md) |
| §12–15 | [design/governance/compliance-and-roadmap.md](design/governance/compliance-and-roadmap.md) |
| Appendix A.1 | [design/threat-model/README.md](design/threat-model/README.md) |
| Appendix A.2–3 | [design/threat-model/hot-cold-paths.md](design/threat-model/hot-cold-paths.md) |
| Appendix A.4–5 | [design/threat-model/kms-and-relay.md](design/threat-model/kms-and-relay.md) |
| Appendix A.6–8 | [design/threat-model/residual-risks.md](design/threat-model/residual-risks.md) |

---

## Other entry points

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — a one-page, high-level ASCII map (hot/cold path, regions, KMS) — the gentlest on-ramp.
- **[OIDC-LOGIN-FLOW.md](OIDC-LOGIN-FLOW.md)** — step-by-step sequence diagrams of the Authorization Code + PKCE flow (§11.2), the most complex sequence in the system.
- **[README.md](README.md)** — the feature/plan index (as-built capabilities and future work).

> **Cross-reference note:** the `§`-numbering scheme is preserved across all files so existing doc cross-references (e.g. `design_refs: [§3.2]` in feature frontmatter) continue to resolve via this table.
