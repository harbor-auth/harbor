# Threat Model — Control Plane, Residual Risks & Day-One Mitigations

> **DESIGN Appendix A.6–A.8** · [↑ DESIGN index](../../DESIGN.md) · prev: [kms-and-relay](kms-and-relay.md)

## Global control plane — §5.3

| STRIDE | Threat (concrete) | Mitigation |
|---|---|---|
| **S** | Fake **region resolver**; **RP-registry poisoning** | **Signed static config** + TLS; the plane holds **no PII/keys**, so spoofing it leaks nothing sensitive (§5.3). |
| **T** | Tamper an RP's `redirect_uri`/`sector` to hijack codes | **Signed registry**; **exact `redirect_uri` match** at `/authorize` (§11.7); reviewed RP registration. |
| **R** | Dispute over an RP registry change | **Change-audited** registry. |
| **I** | Disclosure of what the plane holds | **PII-free by design** (§5.3) — a breach leaks RP metadata + routing only, **no user data**. |
| **D** | Resolver becomes a **global chokepoint** | Resolver **reads only the region prefix** and is **cacheable / replaceable by signed static regional config** (§5.1, §5.3); not on the per-auth data path. |
| **E** | Compromise → **pivot into a region** | Control plane holds **no keys and no PII** and **cannot authenticate as a user**; **regions are isolated** (§5.4) so there is no lateral path into a jurisdiction's data. |

## Cross-cutting residual risks & assumptions

- **Operator-with-key-access correlation:** as stated honestly in §3.2.4, an operator holding a *specific* user's key *could* correlate that one user across RPs — but only **per-user, audited, non-bulk**. There is **no global secret** that deanonymizes everyone. This is a deliberate, disclosed residual.
- **HSM vendor trust:** we assume the KMS/HSM boundary holds; a vendor-level compromise is out of our direct control (mitigated by per-region isolation and rotation).
- **KEK bulk-unwrap (population-level risk):** the regional KEK wraps every per-user DEK in the region. While PPID's per-user secret limits blast radius at the DEK layer, the KEK itself is a population-level single point of failure. The KEK must be HSM-bound, non-exportable, and its API must expose **no bulk-unwrap operation** — only per-key unwrap with individual audited calls (§3.2.1, §7.3). Coercion of the KEK bypasses the per-user isolation guarantee.
- **Supply chain:** malicious dependency or build tampering — mitigated by **reproducible builds** (§2.2) and **dependency/SAST/secret scanning** (§1.7, §1.8), but never fully eliminated.
- **Recovery social-engineering:** the account-recovery flow is a classic attack surface — mitigated by requiring **≥2 pre-registered methods and no email backdoor** (§7.2), but human factors remain.
- **Bearer-token theft window:** until **DPoP/token-binding** ships (§3.1, phase 2), a stolen access token is usable within its **short TTL** (§3.5). Short TTLs bound, but don't eliminate, this until binding lands.

## Priority mitigations to bake in day-one

The highest-leverage controls — cheap to include now, painful to retrofit:

1. **Asymmetric-only signing alg allow-list** — ES256/EdDSA only; reject `alg:none` and any symmetric/HS fallback (A.2 **E**).
2. **PKCE everywhere** — mandatory for all clients (§11.2).
3. **Exact `redirect_uri` match** — pre-registered allowlist, never redirect to an unvalidated URI (§11.7, A.6 **T**).
4. **Per-user pairwise secret** — no global correlation secret (§3.2).
5. **No bulk-decrypt capability** — structurally absent, not merely policy (§2.3, A.4 **I/E**).
6. **PII-free global control plane** — a control-plane breach must leak zero user data (§5.3).
7. **Region isolation** — no cross-region PII, keys, or lateral auth path (§5.4).
