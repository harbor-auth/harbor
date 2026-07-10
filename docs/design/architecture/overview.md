> **DESIGN §4** · [↑ DESIGN index](../../DESIGN.md) · next: [routing](routing.md)

# High-Level Architecture

### 4.1 Guiding split: HOT path vs COLD path

```
                          ┌────────────────────────────────────────────┐
                          │              EDGE (per region)               │
        RP / Browser ───► │  Anycast + Ingress + CDN/edge cache          │
                          │   • /jwks.json         (cached, static-ish)  │
                          │   • /.well-known/*      (cached)             │
                          │   • token verify assets                     │
                          └───────────────┬───────────────┬─────────────┘
                                          │               │
                             HOT (stateless, cacheable)   COLD (stateful)
                                          │               │
                    ┌─────────────────────▼───┐   ┌───────▼────────────────────┐
                    │   auth-hot service       │   │   management plane          │
                    │   • /authorize (start)   │   │   • dashboard API (BFF)     │
                    │   • /token (code→token)  │   │   • RP/client registration  │
                    │   • /jwks, discovery     │   │   • consent management      │
                    │   • verify/introspect    │   │   • MFA/passkey enrollment  │
                    │   stateless + Redis cache │   │   • audit log query/export  │
                    └───────────┬──────────────┘   └───────────┬────────────────┘
                                │                              │
                    ┌───────────▼──────────────────────────────▼────────────┐
                    │   Regional data plane (this jurisdiction ONLY)          │
                    │   Postgres (primary + read replicas)  •  Redis          │
                    │   Regional KMS/HSM (per-region root keys)               │
                    └─────────────────────────────────────────────────────────┘
```

### 4.2 Modular monolith to start

One Go binary, **strong internal module boundaries** (packages with clear interfaces), deployable as separately-scaled processes via build tags / config so the **hot path scales independently** from the start:

- `oidc` — OP endpoints (authorize, token, jwks, discovery, introspect, userinfo).
- `webauthn` — passkey registration & assertion.
- `mfa` — TOTP, recovery codes, step-up.
- `identity` — users, credentials, pairwise-subject derivation.
- `clients` — RP registry & consent/grants.
- `audit` — append-only auth events.
- `crypto` — envelope encryption, key management, signing.
- `cache` — Redis + in-proc caches.
- `region` — region resolution & routing helpers.
- `addons/ageproof` — (future) verifiable-credential age proofs.

Split into separate services **only** where scale demands (the `oidc`/verify path first).

### 4.3 What we store — and what we deliberately DON'T

**We store (per region, encrypted at rest):**
- User account (opaque id, home region, status)
- Credentials: passkey public keys + WebAuthn metadata; optional password hash (Argon2id)
- MFA factors (encrypted TOTP secrets, hashed recovery codes)
- `user_pairwise_secret` (encrypted) for PPID derivation
- RP grants/consents (which RP, which scopes, when)
- Sessions & refresh tokens (opaque, hashed)
- Audit events (auth successes/failures the *user* can see)

**We deliberately DON'T store:**
- Any cross-RP behavioral profile
- RP-side activity ("what you did inside the app")
- Third-party tracking identifiers / ad data
- Plaintext secrets or recovery codes
- A globally-joinable "user → all RPs → real identity" table exposed to anyone

### 4.4 Encryption at rest

- **Envelope encryption**: per-user **Data Encryption Key (DEK)**, wrapped by a **regional Key Encryption Key (KEK)** held in that region's KMS/HSM.
- Sensitive columns (TOTP secrets, pairwise secret, recovery material, optional PII claims) are encrypted with the user DEK.
- **Crypto-shred on erasure**: destroy the user DEK → data is unrecoverable, satisfying GDPR erasure even against immutable backups.
