> **DESIGN §3.2 (2/2)** · [↑ DESIGN index](../../DESIGN.md) · prev: [ppid](ppid.md) · next: [tokens](tokens.md)

# PPID — Privacy Guarantees, Comparisons & Edge Cases

## 3.2.4 Why even Harbor struggles to correlate users across RPs

This is a *strong-but-honest* guarantee, and it's worth being precise about it:

- There is **no plaintext `user → all RPs` table** exposed anywhere in the system. RPs only ever see their own per-sector `sub`.
- To join a single user across RPs, an operator would have to **decrypt that user's `pairwise_secret`** (KEK/HSM-gated, **audited**, with **no bulk-decrypt** capability) and recompute the HMAC per RP. That is **deliberately expensive, per-user, and auditable** — not a casual `SELECT`.
- **Honest framing:** Harbor-as-operator *could* compute a correlation *with* key access for a *specific* user — we don't claim mathematical impossibility. What we claim (and design for) is that it is **non-casual, one-user-at-a-time, audited, and detectable**, with **no global secret** that unlocks everyone. Contrast a naïve global-salt scheme, where one leaked secret silently deanonymizes the entire user base.

**Additional correlation surfaces that PPID does not close (and how they're handled):**

| Surface | Why it exists | How it's constrained |
|---|---|---|
| **SSO session (transient)** | Harbor *must* resolve browser session → real user in order to mint the right per-RP PPID. Transient cross-RP observation is structurally unavoidable for any SSO provider. | Hot-path **operational logs carry no per-user identifiers** (§6.5.3); session data is short-TTL and region-local; Harbor commits to not *persisting* or *building on* this transient signal. |
| **Relay email (persistent index)** | `relay_alias → real_email → user` is a co-equal correlation surface — in some ways larger than `sub`, since it maps to a real-world identifier. | Treated with **identical protection to `pairwise_secret`**: random, unlinkable per `(user, RP)`, envelope-encrypted, region-local, never logged (§7.5.1–§7.5.5). |
| **Grants reverse-index (deliberate capability)** | GDPR self-serve *requires* "show me all RPs I've connected" → a `user → all PPIDs` reverse lookup must exist. | This is a **controlled correlation point**: accessible only to the authenticated user themselves via the dashboard, and to audited admin ops. It is not a flaw; it is disclosed and access-controlled. |
| **Passkey credential (internal join key)** | Harbor is the WebAuthn RP; one credential authenticates the user across all downstream RPs — not leaked to RPs, but a Harbor-internal per-user handle. | Never exposed outside Harbor; region-local; covered by the same DEK/KEK envelope. |

**Net result:** RPs **cannot** join user identities across services at all; Harbor can only do so per-user, behind audited key access — a boundary that our open-source + third-party-audit posture (§2.2) makes verifiable. The residual surfaces above are disclosed, constrained, and access-controlled rather than absent. See §3.2.7 for the consolidated three-tier summary.

## 3.2.5 Comparison: Apple vs Google vs Harbor subject identifiers

| Provider | `sub` scope | Correlation boundary |
|---|---|---|
| **Google** | Stable **per Google account**, paired with the real email | Trivial cross-app correlation (the real email is a universal key). |
| **Apple** | Stable **per developer team** | Blocks cross-*company* correlation, **but a single company with many apps can correlate you across *all* of them** (they share one team `sub`). |
| **Harbor (PPID)** | Stable **per RP registration / sector** | Tightest boundary: even two apps from the same company are separate RPs ⇒ **different `sub`s** (unless they deliberately share a `sector_identifier`). See §2.4 for positioning. |

## 3.2.6 Edge cases

- **RP re-registration / sector change:** if an RP's `sector_identifier` changes (e.g., it re-registers under a new sector), the derived `sub` **changes**, which the RP will experience as a *new* user. This is the standard OIDC pairwise trade-off; RPs that need continuity must keep a **stable `sector_identifier_uri`**, and any intentional migration must be handled as an explicit **account-linking** step on the RP side.
- **The `sub` on the wire:** the `pairwise_sub` derived here is precisely what is emitted as the ID-token `sub` claim in the §11.2 walkthrough — RPs key their local account off it.
- **Result:** **RPs cannot join user identities across services**, and we deliberately keep no globally-joinable "one user id → all RPs" table exposed to RPs.

## 3.2.7 Honest summary: three-tier privacy guarantee

Harbor's privacy promise bundles three guarantees of **different strength**. Being explicit about which tier is which keeps the claim honest and avoids the overclaiming that would undermine trust.

| Tier | Claim | Strength | How to verify |
|---|---|---|---|
| **1 — RP unlinkability** | Two colluding RPs comparing the `sub` they hold for the same user (identified out-of-band) see unrelated HMAC outputs — they cannot join identities by comparing subjects. | **Verifiable by construction.** Follows from the HMAC key being per-user and the sector being per-RP. Any third party can verify this from the source code alone. | Read `internal/identity/ppid.go`; run the non-correlation test vectors in `ppid_vectors_test.go`. |
| **2 — Operator technical constraint** | Harbor is architecturally constrained from *casual* or *bulk* correlation: no global secret, no bulk-decrypt API, per-user DEK, grants reverse-index is access-controlled + audited. Correlating one user requires per-user key access behind audited HSM ops. | **Strong, but trust-the-operator** until reproducible builds + transparency log ship (Phase 3, §2.2). The published source code is clean; the deployed binary must be verified to match it. | Reproducible builds (planned); third-party audits (planned); transparency log of key ops (planned). |
| **3 — Log / telemetry minimization** | Harbor commits to not persisting or building on the transient cross-RP signal it unavoidably touches during SSO. Hot-path logs carry no per-user identifiers; operational logs ≠ audit log; no behavioral profiling. Traffic/timing correlation (IP, geo) is **out of scope** — Harbor is not Tor; mitigation is log minimization only. | **Policy + design convention**, enforced by deny-by-default log field allow-listing (§6.5.3) and code review, but not cryptographically enforced. An insider could violate this without breaking the crypto. | Open-source audit; §6.5.7 privacy invariants for observability; `@harbor-reviewer` enforces in review. |

**Restatement of the headline:** *Harbor's stored identity model is unlinkable across RPs by construction (Tier 1 — independently verifiable). Harbor is architecturally constrained from casual or bulk operator correlation (Tier 2 — strong, attestation-dependent). Harbor commits to not persisting the cross-RP signal it must transiently touch during SSO (Tier 3 — policy + design convention, open to audit).*

This is stronger than Apple (Tier 1 is per-RP, not per-developer-team; §2.4.5) and stronger than any policy-only promise. It is honestly weaker than a claim of mathematical impossibility — which no SSO provider can make.
