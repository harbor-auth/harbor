# Harbor — Production-Readiness Audit

> **Authored:** 2026-07-22 · **Method:** Fable deep-reasoning audit of the full
> codebase (`cmd/`, `internal/`, migrations, and design docs — verified against
> the actual code, not the plan graph).
>
> **Scope:** the state of the tree **after all 16 Wave 4/5 Weft features land**
> (assuming every in-progress feature completes as specced).
>
> **Bottom line:** even with all 16 features landed, Harbor **cannot take
> production traffic.** Seven critical blockers remain — the most dangerous
> being `FixedAuthSource` (**every user is the same user**) and the
> `webauthn-db-wiring` failure (**passkeys lost on restart**). On top of the
> blockers, **six Phase-0 MVP features have no plan doc and no Weft feature at
> all**: TOTP, HSM signing, admin auth, client auth, RFC 7009 revoke (endpoint
> shipped; enforcement path still open), and logout.

This audit is the source for **[Wave 6 — Phase-0 Critical Fixes](README.md#wave-6--phase-0-critical-fixes-2026-07-production-readiness-audit)**.

---

## 🔴 Section 1 — Critical Blockers

*Must fix before **ANY** production traffic. Each is an independent
auth-bypass, identity-integrity, or key-management hole.*

| # | Item | File / Symbol | Covered by the 16 Weft features? |
|---|---|---|---|
| **1.1** | **Total auth bypass** — `FixedAuthSource` hardcodes `demoUserID` in **both** the DB and in-memory hot paths; every `/authorize` issues tokens for the same demo user regardless of caller. The code logs its own confession: *"SCAFFOLD: FixedAuthSource wired in DB path — /authorize always authenticates as the hardcoded demo user."* | `cmd/harbor-hot/main.go` → `oidc.NewFixedAuthSource("00000000-…-000000000001")` wired into `PPIDSessionResolver` | `bff-flow-wiring` (`feat_90b6e7b2`) ✅ **completed** — the BFF seam (`Service.AuthorizeWithUser` / `ValidateAuthorizeRequest`) exists, but **`main.go` still constructs the legacy `Authorize` path with `FixedAuthSource`**. This is a **wiring gap**, not a feature gap — the single worst item in the codebase. |
| **1.2** | **Login via `?user_id` query param** — `devUserResolver{}` selects *which* user to challenge from a client-supplied `user_id` URL parameter. The passkey assertion is still proven (so it's not raw impersonation), but there is no email/username → user lookup, user enumeration is trivial, and there's no production login UX. | `cmd/harbor-mgmt/bff.go` (`devUserResolver`) + `cmd/harbor-mgmt/main.go:219` (`bff.NewLoginHandler(…, devUserResolver{})`) | `discoverable-login` (`feat_12ee5a09`, in_progress) is the intended fix — **must verify it actually replaces `devUserResolver` in `main.go`**, not merely add a resolver alongside it (cf. the `webauthn-db-wiring` "built but never wired" pattern). |
| **1.3** | **WebAuthn credentials in-memory — data loss on every restart** — `webauthn.NewInMemoryStore()` is hardwired unconditionally, even when `DATABASE_URL` is set. Because passkeys are the **primary** factor (§7.1) and there is no email backdoor (§7.2), a restart **permanently locks out every user**. | `cmd/harbor-mgmt/main.go` → `store := webauthn.NewInMemoryStore()` | `webauthn-db-wiring` (`feat_ac6b4036`) **❌ FAILED.** The fix already exists (`internal/webauthn/store_db.go`: `DBStore`, `NewDBStore(q).WithPool(pool)`, atomic `AddCredentialAndActivateUser` — complete, tested, compile-time asserted against `Store`). Remediation is **~5 lines in `main.go`.** Cheapest critical fix in the audit — **re-launch immediately** (`webauthn-db-rewire`, P0). |
| **1.4** | **No HSM/KMS anywhere — signing keys and KEKs are process-local** — `crypto.NewLocalSigner()` generates an ephemeral in-process signing key (tokens don't survive a restart; violates §7.3 "private key never leaves the HSM"). `crypto.NewLocalKeyProvider()` keeps the KEK as an env var. Both `hsmSigner` and `kmsKeyProvider` return `ErrHSMNotImplemented` on every method. | `cmd/harbor-hot/main.go` (`NewLocalSigner`, `NewLocalKeyProvider`); `internal/crypto/signer_hsm.go`; `internal/crypto/keyprovider_kms.go` | `kms-provider-integration` covers the **KEK** only. **The HSM-backed *signer* is a completely separate, uncovered work item** with no plan doc and no Weft feature → `hsm-signing-key` (P1). |
| **1.5** | **Unauthenticated admin endpoints** — `POST /admin/revoke-jwt` and `/admin/keys/*` have **zero `Authorization` header checks**, and they sit on the internet-facing `harbor-hot` binary. Anyone who can reach the pod can revoke tokens or manipulate keys. | `internal/oidcapi/revoke_jwt.go`; `internal/oidcapi/admin_keys.go` | **Not in the 16 features. No plan doc.** → `admin-endpoint-auth` (P0). |
| **1.6** | **No client auth on `/token`** — confidential clients pass no secret; the token endpoint never verifies `client_secret`. `0012_client_registration` stores `client_secret_hash`, but nothing reads it at token time (`internal/oidcapi/token.go` comments the check as "inert"). | `internal/oidcapi/token.go` | **Not in the 16 features. Not in any plan doc.** → `client-secret-auth` (P0). |
| **1.7** | **ACR/AMR claims are hardcoded lies** — `urn:harbor:ac:webauthn` / `["hwk","user"]` are emitted regardless of the actual authentication method. The moment TOTP or recovery-code auth exists, these claims will actively mislead RPs about how the user authenticated. | `internal/oidc/token.go` (`acr` / `amr`) | Not addressed anywhere → `acr-amr-dynamic` (P2, gated on `totp-mfa`). |

---

## 🟠 Section 2 — Compliance Blockers

*Required for lawful GDPR/CCPA operation in the EU/US. Most are **in flight**
on Weft (Wave 5) but not yet landed or verified end-to-end.*

| # | Item | Status |
|---|---|---|
| **2.1** | **DSAR export / delete (data subject access requests)** — users must be able to export and delete their data; deletion must crypto-shred the per-user DEK so ciphertext is unrecoverable. | `compliance-export` (`feat_04c21ab3`, ⏳ proposed on Weft). Depends on `user-audit-trail` (for the export manifest) and `envelope-encryption-kms` ✅ (for crypto-shred). **Verify the delete path actually destroys the DEK, not just rows.** |
| **2.2** | **Audit-log completeness** — every security-relevant action (enroll, consent grant/revoke, key op, admin action, login) must be recorded in a tamper-evident audit trail. | `user-audit-trail` (`feat_c2d5e191`, ⏳ proposed). `audit_events` table + queries exist; **verify all seven blocker-adjacent actions above emit audit rows** — especially admin ops (1.5) once authenticated. |
| **2.3** | **User-data deletion cascade** — deleting a user must cascade across credentials, MFA factors, sessions, consent grants, and audit-retention windows without orphaning PII in any regional store. | Partially covered by `compliance-export`; **the cascade + retention policy is not fully specced.** Needs an explicit deletion-cascade map before launch. |
| **2.4** | **Regional data-pinning enforcement** — PII must never leave its jurisdiction; the region prefix in the issuer must route with **no global user lookup** (§5.1). | `regional-data-residency-routing` (`feat_8ec115c6`, ⏳ proposed / `feat_733f3eba` ✅ prior completed). **Verify the guard does no global `user_id → region` lookup** (the home-region source-of-truth decision, OpenSpec Decision 5 / REQ-005). |
| **2.5** | **Consent-revocation cascade** — revoking consent for an RP must invalidate that RP's live grants/tokens, not just flip a UI flag. | `consent-management-ui` (`feat_28ba9372`, ⏳ proposed), on top of `consent-ledger` ✅. **Verify revocation cascades into the revocation outbox / bloom filter**, so already-issued tokens die. |

---

## 🟡 Section 3 — Missing Phase-0 MVP Features

*Protocol- or product-required for an MVP OpenID Provider, but with **no plan
doc and no Weft feature**. These are net-new build items, not wiring fixes.*

| # | Feature | Evidence in tree | Notes |
|---|---|---|---|
| **3.1** | **TOTP / MFA** | `mfa_factors` table + `internal/gen/db/mfa_factors.sql.go` (`CreateMFAFactor`, `GetMFAFactor`, `DeleteMFAFactor`) exist. **No service, no API, no UI.** | §7.1 names TOTP as the secondary/step-up factor for users without passkeys. The schema is ready; the enrollment + verification service is not. → `totp-mfa` (P1). |
| **3.2** | **HSM-backed signing key** | `internal/crypto/signer_hsm.go` — `hsmSigner` returns `ErrHSMNotImplemented` on every method. | Distinct from the KEK KMS (`kms-provider-integration`). Without it, signing keys are ephemeral and tokens don't survive a restart (see 1.4). Long-lead. → `hsm-signing-key` (P1). |
| **3.3** | **End-session / logout** | No RP-Initiated Logout endpoint; no Front-Channel/Back-Channel logout. `sessions` table is ready. | OpenID Connect Session Management / RP-Initiated Logout. RPs cannot end a Harbor session today. → `end-session-logout` (P1, leaf). |
| **3.4** | **ACR/AMR dynamic claims** | `internal/oidc/token.go` emits fixed `acr`/`amr`. | Fix after TOTP lands so claims reflect the real factor(s) used. → `acr-amr-dynamic` (P2, **gated on `totp-mfa`**). |

> **RFC 7009 note:** the `token-revocation-endpoint` (RFC 7009 `POST /revoke`)
> has **shipped** as a surface, but end-to-end enforcement should be re-verified
> once `admin-endpoint-auth` (1.5) and `client-secret-auth` (1.6) land, since
> revocation authorization leans on client authentication.

---

## Wave 6 — Launch Queue

Prioritized build order. **The four P0 fixes are independent roots — launch all
four in parallel.** `hsm-signing-key` is long-lead — start it early.

| # | Slug | Priority | Blocker # | Est. effort | Dependency |
|---|---|---|---|---|---|
| 1 | `webauthn-db-rewire` | **P0** | 1.3 | 1–2 h | root (re-launch `feat_ac6b4036`) |
| 2 | `fix-auth-bypass` | **P0** | 1.1 | 2–4 h | root (consumes `bff-flow-wiring` ✅ seam) |
| 3 | `admin-endpoint-auth` | **P0** | 1.5 | 2–4 h | root |
| 4 | `client-secret-auth` | **P0** | 1.6 | 4–8 h | root (reads `client_secret_hash`) |
| 5 | `hsm-signing-key` | **P1** | 1.4, 3.2 | 1–2 w | root (start early; long-lead) |
| 6 | `totp-mfa` | **P1** | 3.1 | 1 w | root (schema ready) |
| 7 | `end-session-logout` | **P1** | 3.3 | 1 w | leaf |
| 8 | `acr-amr-dynamic` | **P2** | 1.7, 3.4 | 2–4 h | **gated on `totp-mfa`** |

**Recommended first move:** `webauthn-db-rewire` — it's ~5 lines, the store is
already built and tested, and it closes the passkey-loss-on-restart hole that
can permanently lock out every enrolled user.

---

## Appendix — Audit Evidence

Files examined during the audit (representative, not exhaustive):

| Area | Files |
|---|---|
| Hot-path wiring | `cmd/harbor-hot/main.go` |
| Mgmt-path wiring | `cmd/harbor-mgmt/main.go`, `cmd/harbor-mgmt/bff.go` |
| Auth / issuance | `internal/oidc/service.go`, `internal/oidc/issuer.go`, `internal/oidc/token.go` |
| Admin surface | `internal/oidcapi/revoke_jwt.go`, `internal/oidcapi/admin_keys.go`, `internal/oidcapi/token.go` |
| WebAuthn store | `internal/webauthn/store_db.go`, `internal/webauthn/store.go`, `internal/webauthn/user.go` |
| Crypto / keys | `internal/crypto/keyprovider.go`, `internal/crypto/keyprovider_kms.go`, `internal/crypto/signer.go`, `internal/crypto/signer_hsm.go` |
| Clients / DB | `internal/clients/users.go`, `internal/gen/db/mfa_factors.sql.go`, `internal/gen/db/*.sql.go` |
| Design / policy | `docs/DESIGN.md`, `docs/ARCHITECTURE.md`, `docs/design/security/overview.md`, `docs/design/threat-model/`, `docs/design/governance/compliance-and-roadmap.md` |

> **Anti-drift note:** this is a point-in-time audit. When any Wave-6 fix lands,
> update the matching row here (strike it, or move it to a "Resolved" log) in the
> **same** change — same rule as `@docs reconcile` keeps `doc ↔ code` honest.
