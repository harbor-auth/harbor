> **DESIGN §2.1–2.3** · [↑ DESIGN index](../../DESIGN.md) · next: [privacy-positioning](privacy-positioning.md)

# Product Positioning & Trust Model

## 2.1 What we sell: a trust guarantee

The product is not "another login button" — it's a **promise that is technically enforced and independently verifiable**:

- We **never** build a profile of you.
- We **never** *persistently* tell RP-A that you also use RP-B (no stored cross-RP correlation). *(Honest footnote: during SSO Harbor must transiently resolve which user you are in order to issue the correct per-RP PPID — see §3.2.4 and §3.2.7 for what this means and doesn't mean.)*
- We **never** sell, share, or mine your data.
- We authenticate you **only** with RPs you have explicitly connected.
- Your **audit log is yours** — you can see, export, and (subject to fraud/legal retention windows) delete every authentication event.

## 2.2 How we make privacy *verifiable*, not just a promise

| Technique | What it guarantees |
|---|---|
| **Pairwise Pseudonymous Identifiers (PPID)** | Each RP gets a *different* `sub` for the same user. **RP-unlinkability is verifiable by construction** (two colluding RPs comparing `sub`s see unrelated HMAC outputs — provable from the code alone). **Operator non-correlation is attestation-dependent**: Harbor is technically constrained (per-user key, no global secret, no bulk-decrypt) but proving the *deployed binary* matches the published source requires reproducible builds + a transparency log (planned, §3.2.7). See §3.2.4 for the full honest framing. |
| **Data minimization** | We store the minimum needed to authenticate. Claims released to an RP are per-grant and consented. |
| **No behavioral logging** | The hot auth path emits only aggregate, non-identifying metrics. No per-user analytics, no ad SDKs, no third-party trackers. |
| **User-owned audit log** | Every `AuthEvent` is visible to the user in their dashboard and exportable. |
| **Envelope encryption w/ per-user keys** | Even with DB access, records aren't readable without the KMS/HSM-held keys; supports crypto-shred on erasure. |
| **Open source + reproducible builds** | The OP core is auditable. Anyone can verify what the code does. |
| **Third-party security audits + transparency reports** | Periodic external audits; published transparency reports on legal requests. |
| **(Later) Transparency log** | Append-only, publicly-verifiable log of *policy* events (e.g., key rotations, RP registrations) — never user data. |

## 2.3 Threat model

| Adversary | Concern | Mitigation |
|---|---|---|
| **The operator (us)** | We could be tempted (or compelled) to track users | PPID by construction; no profiling code paths; per-user encryption; minimal logs; open source so deviations are detectable |
| **Relying Parties** | RP tries to correlate users across apps, or over-collect | PPID; per-grant consented claims; no "email as universal ID" unless user opts in |
| **Network attackers** | MITM, token theft | TLS everywhere, HSTS, token binding/DPoP (phase 2), short-lived tokens |
| **Phishing / credential stuffing** | Account takeover | **Passkeys (WebAuthn) as primary factor** — phishing-resistant by design; passwords optional/deprecated |
| **Account takeover via recovery** | Recovery is the classic weak link | Multi-path recovery requiring possession + knowledge; no single email-reset backdoor (see §7.2) |
| **Legal / government requests** | Compelled disclosure | Per-jurisdiction data residency; we can only ever disclose what we hold (which is minimal); published transparency reports; PPID means we can't hand over a cross-service graph we don't have |
| **Insider threat** | Rogue employee | HSM-guarded keys, least privilege, audited admin actions, no bulk-decrypt capability |
