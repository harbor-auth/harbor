# Threat Model — Hot Path & Cold Path

> **DESIGN Appendix A.2–A.3** · [↑ DESIGN index](../../DESIGN.md) · prev: [README](README.md) · next: [kms-and-relay](kms-and-relay.md)

## Hot path (`harbor-hot`) — §4.1, §6.1

| STRIDE | Threat (concrete) | Mitigation |
|---|---|---|
| **S** | Forged JWT, stolen bearer token, phishing of credentials | Asymmetric **JWKS-verified** signatures (§3.5); **passkeys** are phishing-resistant (§7.1); **PKCE mandatory** (§11.2); **DPoP/token-binding** planned (§3.1, phase 2) to bind tokens to a client key. |
| **T** | Claim/token tampering; **JWKS poisoning** (swap in an attacker key) | Signature verification on every token; JWKS served over **TLS** and matched by **`kid`** (§3.4); keys originate only from the HSM (§7.3). |
| **R** | User denies initiating an authentication | **User-owned audit log** of every `AuthEvent` (§4.3, §11.6). |
| **I** | Token/claim leakage; **cross-RP correlation** from `sub` | **Minimal claims** in tokens (§3.3); **PPID** `sub` per RP (§3.2); TLS in transit; short TTLs (§3.5). |
| **D** | Verification flood; key-rotation storms; auth-code brute force | **Stateless offline verify** — resource servers verify via cached JWKS with no callback (§6.1); **edge/CDN cache** for JWKS/discovery; **HPA** autoscaling (§6.2); **rate-limiting** on ephemeral signals (§6.4). |
| **E** | Scope/`aud` escalation; **algorithm-confusion** (`alg:none`, RS↔HS downgrade) | **Strict signing-alg allow-list** (ES256/EdDSA only — **no `alg:none`, no symmetric fallback**); exact **`scope`/`aud`/`redirect_uri`** checks (§11.7). |

## Cold path / management plane — §4.1, §6.2

| STRIDE | Threat (concrete) | Mitigation |
|---|---|---|
| **S** | Session hijack; **CSRF** on dashboard actions | **Passkey step-up** for sensitive ops (§7.1); **`HttpOnly`/`SameSite`** cookies (§7.4); `state` on OAuth flows (§11.7). |
| **T** | Grant/consent tampering; **mass-assignment** on management APIs | Per-object authorization checks; **contract-validated inputs** (§1.2) — no vague payloads; deny-by-default fields. |
| **R** | User disputes a grant/revocation | **Audit log** records grant add/remove and admin actions (§4.3). |
| **I** | PII over-exposure via dashboard/API responses | Authorization + **data minimization** (§2.2); **region residency** so responses never carry cross-region PII (§5). |
| **D** | Enrollment / endpoint abuse floods the management plane | **Rate-limiting**; management plane **scales separately** from the hot path so abuse can't starve auth (§6.2). |
| **E** | **IDOR**; escalate to another user or **another region**; admin abuse | **Per-object authz**; **region checks** on every access; **least-privilege, audited admin** actions with **no bulk-decrypt** (§2.3). |
