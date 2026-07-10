> **DESIGN §3.1, §3.3–3.5** · [↑ DESIGN index](../../DESIGN.md) · prev: [ppid-guarantees](ppid-guarantees.md)

# Protocol Stack & Token Strategy

## 3.1 Recommended stack

- **OpenID Connect (OIDC)** — we are a full **OpenID Provider (OP)**.
- **OAuth 2.1** semantics — Authorization Code flow **+ PKCE mandatory** for all clients (public and confidential). No implicit flow, no ROPC.
- **FIDO2 / WebAuthn / passkeys** — the **primary, phishing-resistant** authentication factor. Passwords are optional and, where used, always backed by a second factor.
- **SAML 2.0** — **deferred**. Only add when we pursue enterprise deals; it complicates the privacy story (SAML NameIDs, enterprise IdP semantics). Keep the core OIDC-clean; bolt SAML on as an isolated bridge later.
- **DPoP / token binding** — phase 2, to bind tokens to a client key and defeat token replay.

## 3.3 Token strategy — hybrid (this is the performance crux)

Two token classes, chosen deliberately for the privacy/perf trade-off:

| Token | Type | Verified by | Lifetime | Why |
|---|---|---|---|---|
| **ID Token** | Asymmetric-signed **JWT** (ES256/EdDSA) | RP, offline via **JWKS** | Short (~5 min) | RPs expect a JWT; standard OIDC. Contains only consented claims + PPID `sub`. (We deliberately pick **ES256/EdDSA** over RS256 for smaller tokens/signatures and faster verification.) |
| **Access Token** | **Asymmetric JWT** (default) *or* **opaque reference** (privacy-max mode) | Resource server via JWKS *or* introspection | Short (~5–15 min) | JWT = **zero DB hit on the hot path** → millions/sec cheaply. Opaque = revocable/introspectable for high-sensitivity RPs. RP chooses per-client. |
| **Refresh Token** | **Opaque, rotating**, one-time-use | Harbor only, DB-backed | Long, sliding | Enables revocation & session management; rotation detects theft. Not on the hot path. |

**Why JWT-by-default on the hot path:** verification is a signature check against a **cached JWKS** — no network call, no DB. This is what makes "millions/sec, low cost" achievable (see §6). Revocation of short-lived JWTs is handled by short TTLs + a small, edge-replicated **revocation bloom filter** for emergency kill.

**Privacy note on JWTs:** we keep ID/access token claims *minimal* (PPID `sub`, `aud`, `iss`, `exp`, and only consented claims). No email/name unless the RP's grant includes it.

## 3.4 Per-region issuer & discovery

Each region is its **own OIDC issuer**:

- `https://eu.harbor.id`, `https://us.harbor.id`, `https://au.harbor.id`, …
- Each publishes its own `/.well-known/openid-configuration` and `/.well-known/jwks.json`.
- The `iss` claim tells the RP (and any edge) exactly which region minted the token → routing and key discovery need **no global lookup**.

## 3.5 Token lifecycle & revocation

This section makes explicit the central tension behind the hybrid-token choice in §3.3.

### 3.5.1 The core tension: a pure JWT cannot be revoked

A JWT is **self-contained and stateless**: the RP/resource server validates it by checking the signature against our public key (JWKS) and reading `exp` — **without ever calling back to Harbor**. That offline check is exactly what makes the hot path fast enough for millions/sec (§6.1). But it also means that **once issued, a JWT is valid until it expires** — there is no built-in "off switch". Speed *comes from* not talking to us; revocation requires talking to someone. These are in direct tension.

```
  1. sign in    ┌──────────┐  publishes public keys
  ────────────► │  Harbor  │  at /.well-known/jwks.json
                │   (OP)   │────────────┐
                └──────────┘            ▼
  2. JWT (signed, exp=+10m)      ┌──────────────┐
  ────────────────────────────► │ Relying Party │  verifies signature
                                 │  verifies     │  OFFLINE — no call
                                 │  LOCALLY  ⚡  │  back to Harbor.
                                 └──────────────┘
```

### 3.5.2 The mechanisms, and what Harbor uses

| Mechanism | Revocation latency | Cost on hot path | Harbor usage |
|---|---|---|---|
| **Short-lived JWT + opaque refresh token** | ≤ access-token TTL | none (offline verify) | **Primary.** Access token ~5–15 min; "revoke" = delete the DB-backed refresh token, so no new access tokens are minted. |
| **Opaque access token + introspection** | instant | DB/network per call | **Opt-in per-RP** for high-security relying parties that need an instant kill. |
| **Revocation deny-list (bloom filter)** | near-instant | one in-memory lookup | **Emergency kill.** Compact, edge-replicated `jti`/session filter for compromised tokens; rare false positives fall back to introspection (§6.3). |
| **Signing-key rotation** | instant, mass | none | **Nuclear option** — suspected key compromise; rotate the regional JWKS `kid`. |

**The mental model:** with JWTs you don't revoke the *token*, you revoke the *ability to get a new one* — and keep the token short-lived enough that the difference doesn't matter.

### 3.5.3 Harbor's concrete policy

| Scenario | Mechanism | Revocation latency |
|---|---|---|
| Default hot path (most RPs) | Short-lived JWT (~10 min) + opaque refresh token in regional DB | ≤ token lifetime |
| "Log out everywhere" / revoke app | Delete refresh token(s) for that user↔RP pairing | ≤ token lifetime |
| High-security RPs (opt-in) | Opaque access tokens + introspection (regional cache) | Instant |
| Compromised token(s) | Edge-replicated revocation bloom filter | Near-instant |
| Compromised signing key | Regional JWKS key rotation | Instant (that region) |

**Sovereignty-consistent:** the refresh-token store, introspection cache, and deny-list are all **per-region** (§5), so revocation never requires a cross-jurisdiction lookup.

### 3.5.4 Reference: how Google does it

Google validates the same trade-off with a different mix, because *Google itself* is the resource server for its APIs:

- **ID token** = a **JWT**, read **once** by the RP at login, then discarded (the RP creates its own session). Nothing to revoke — it did its one job.
- **Access token** = **opaque** (`ya29.…`), validated server-side by Google → **instantly revocable**.
- **Refresh token** = **opaque**, long-lived, DB-backed → the real "off switch"; removing an app deletes it.

Harbor differs on the *access token*: because our resource servers are **third-party RPs** verifying tokens on their own infra, we default to **short-lived JWT access tokens** (offline-verifiable, for the millions/sec path) and reserve opaque+introspection as the opt-in. Google doesn't need that hot-path optimization because its API traffic is internal.

**Universal rule both designs share:** *never make the revocable, long-lived credential a JWT.* Keep the JWT short-lived and single-purpose; make the long-lived thing (refresh token / session) **opaque and server-side**.
