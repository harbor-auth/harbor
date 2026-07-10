> **DESIGN §12–15** · [↑ DESIGN index](../../DESIGN.md) · prev: [flows/error-cases](../flows/error-cases.md)

# Compliance, Governance, Roadmap & Trade-offs

## 12. Compliance & Governance

- **GDPR / CCPA**: data minimization and purpose limitation are built-in; per-region residency; DSАR (access/export/delete) self-serve in dashboard.
- **Data residency**: enforced by region-encoded identifiers + region-local storage/keys; no cross-region PII replication.
- **Right-to-erasure vs immutable audit**: reconciled via **crypto-shred** (destroy DEK) + minimal, time-boxed, non-identifying security records.
- **Legal / government requests**: we can only disclose what we hold (minimal, region-scoped). PPID means **we don't possess a cross-service identity graph to hand over**. Publish periodic transparency reports.

## 13. Age-Proof Add-On (future)

Privacy-preserving age verification via **verifiable credentials + selective disclosure**, so a user can prove `age_over_18` **without revealing birth date or identity**:

- **Formats**: **SD-JWT VC** (selective disclosure) and/or **ISO/IEC 18013-5 mDL** `age_over_NN` attributes; align with **W3C Verifiable Credentials 2.0** and the **W3C Digital Credentials API**; interoperate with **eIDAS 2.0 / EU Digital Identity Wallet**.
- **ZK / BBS+**: selective disclosure (and eventually ZK predicates) let us present *only* the boolean age assertion.
- **Model**: Harbor acts as issuer/holder-facilitator; the RP gets a signed `age_over_18 = true` and nothing else. Fits the no-tracking ethos perfectly.

## 14. Phased Roadmap / MVP

**Architected day-one (even if not fully scaled): PPID, per-region issuer scheme, JWT hot-path, envelope encryption, and the spec-first/codegen toolchain (§1).** These are hard to retrofit, so bake them in early.

**Phase 0 — MVP (single region, ship in ~months)**
- Go modular monolith: OIDC OP (auth code + PKCE), passkey login, TOTP + recovery codes.
- PPID `sub` from day one.
- Next.js dashboard: connected apps, sessions, passkeys, audit log, GDPR export/delete.
- Postgres + Redis, envelope encryption, JWT tokens verified via JWKS.
- Contracts-first from commit one: `api/openapi` + `api/proto` in place, codegen + spec-lint + breaking-change checks wired into CI.
- One region, but **all identifiers already region-prefixed** so multi-region is additive.

**Phase 1 — Performance hardening**
- Split `auth-hot` from `management`; HPA; edge/CDN JWKS caching; revocation bloom filter; load-test to millions/sec.

**Phase 2 — Multi-jurisdiction**
- Second region (e.g., US alongside EU); global PII-free control plane + region resolver; host-based edge routing.

**Phase 3 — Trust & enterprise**
- DPoP/token binding; social recovery; transparency log; third-party audit; (optional) SAML bridge for enterprise.

**Phase 4 — Add-ons**
- Age-proof verifiable credentials; further selective-disclosure claims.

## 15. Risks, Open Questions & Key Trade-offs

| # | Decision | Trade-off | Recommendation |
|---|---|---|---|
| 1 | **JWT vs opaque access tokens** | JWT = fast/cacheable/no-DB but revocation is coarse; opaque = revocable but needs introspection (DB/network) | **Hybrid**: JWT default (perf), opaque opt-in per-RP for high sensitivity; short TTLs + bloom-filter kill. |
| 2 | **Account recovery** | Strong (no email backdoor) vs user friction / lockout risk | Mandate ≥2 pre-registered methods; encourage multiple passkeys; opt-in social recovery. Communicate clearly. |
| 3 | **Region encoding** | Region-prefixed ids/issuers are simple & lookup-free but "leak" region and complicate account moves | Accept it; region isn't sensitive; support explicit (rare) region migration as a heavy operation. |
| 4 | **zitadel/oidc vs ory/fosite** | zitadel = higher-level/faster to build; fosite = more control/more work | **zitadel/oidc** for MVP velocity; revisit if we need lower-level control. |
| 5 | **Modular monolith vs microservices** | Monolith = fast to build/operate; micro = independent scale | Monolith with clean seams; split **only** the hot path first. |
| 6 | **SAML now vs later** | Enterprise reach vs privacy-model complexity | **Later**, isolated bridge. Keep core OIDC-clean. |
| 7 | **Global control plane existence** | Any global component is a residency/attack risk | Keep it **PII-free** (RP registry + routing only); consider signed static regional config instead. |
| 8 | **RP over-collection** | RPs may demand email/name as universal id, undermining PPID | Default PPID; email/name only via explicit per-grant consent; educate RPs. |
| 9 | **OpenAPI for "every" interface** | One spec language is simpler, but OpenAPI is awkward for gRPC and can't redefine OIDC/WebAuthn | **Spec-first everywhere, best native contract per surface**: OpenAPI (REST), Protobuf (gRPC), SQL/`sqlc` (DB), standards+conformance (protocol edge). All codegen-driven (§1.4). |

**Open questions to resolve next:**
- Which cloud/KMS/HSM per region (AWS KMS+CloudHSM, GCP, or self-hosted Vault+HSM)?
- Exact regional footprint at launch (EU-only first, or EU+US)?
- Business model (per-auth pricing? RP subscription?) — informs the control-plane billing design.
- Do we host the RP-facing consent UI, or offer a headless option?
