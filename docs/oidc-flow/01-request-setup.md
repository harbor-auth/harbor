> **OIDC Flow — Part 1 of 4** · [↑ Overview](../OIDC-LOGIN-FLOW.md) · next: [02-authenticate](02-authenticate.md)

# OIDC Flow — Registration, PKCE Setup & /authorize

## Participants

```
 ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐   ┌──────────────────┐
 │     RP       │   │   Browser    │   │   Harbor-HOT     │   │  Harbor-COLD     │
 │  your app    │   │  user's      │   │  /authorize      │   │  login UI +      │
 │  server-side │   │  browser     │   │  /token  /jwks   │   │  consent screen  │
 └──────────────┘   └──────────────┘   └──────────────────┘   └──────────────────┘
                                                │                        │
                                       ┌────────┴────────┐     ┌────────┴────────┐
                                       │  Regional DB    │     │  Regional KMS   │
                                       │  Postgres+Redis │     │  HSM-held keys  │
                                       └─────────────────┘     └─────────────────┘
```

**Who does what:**

| Participant | Role |
|---|---|
| **RP** | The third-party app (server-side): builds the request, exchanges the code, verifies the token. |
| **Browser** | Routes redirects between RP and Harbor; runs the WebAuthn passkey ceremony. |
| **Harbor-HOT** | Stateless hot path: validates `/authorize` params, issues the code, and handles the back-channel `/token` exchange. §4.1 |
| **Harbor-COLD** | The login/consent UI: passkey authentication, MFA step-up, consent screen (relay email + PPID). §4.1 |
| **Regional DB** | Postgres/Redis — stores auth codes, client registry, grants, pairwise secrets. Per-jurisdiction; never leaves the region. §5 |
| **Regional KMS** | HSM-backed signing keys (ES256/EdDSA). Private keys never leave the HSM boundary. §7.3 |

---

## Step 0 — RP Registration (once, not per-login)

Before any user can log in, the RP registers once with Harbor:

```
    RP (developer, one-time)                       Harbor-COLD
         │                                              │
         │── register client (name, redirect_uris, ───►│
         │   sector_identifier_uri, scopes_allowed)     │
         │                                              │── write relying_parties row
         │                                              │   (client_id, sector_id,
         │                                              │    redirect_uri allowlist)
         │◄── client_id (+ optional client_secret) ─────│
         │                                              │
```

**What's stored per RP:** `client_id`, exact `redirect_uri` allowlist, `sector_id`
(groups redirect URIs for PPID derivation — §3.2.2), `token_format` preference
(`jwt` | `opaque`), `scopes_allowed`. No user data — this row lives in the
**PII-free global control plane** (§5.3).

---

## Step 1 — RP Builds the Request (PKCE Setup)

Before redirecting the user, the RP generates all the per-request cryptographic
material **server-side**:

```
    RP (server-side)
         │
         │  code_verifier  = random 43–128 char URL-safe string  ← kept secret, never sent
         │  code_challenge = BASE64URL( SHA256( code_verifier ) ) ← sent in step 2
         │  state          = random anti-CSRF value               ← stored in RP session
         │  nonce          = random anti-replay value             ← bound into ID token
         │
```

**Why PKCE?** (§11.2, §3.1)

```
  Without PKCE:
    attacker intercepts the authorization code ──► can exchange it for tokens ✗

  With PKCE:
    attacker intercepts the code ──► needs code_verifier to exchange it
    code_verifier was never sent   ──► stolen code is useless             ✓
```

---

## Step 2 — Browser Redirects to `/authorize`

```
    RP                         Browser                    Harbor-HOT
     │                            │                           │
     │── 302 with Location: ─────►│                           │
     │   https://eu.harbor.id/authorize                       │
     │   ?response_type=code                                  │
     │   &client_id=rp_abc123                                 │
     │   &redirect_uri=https://app.example.com/callback       │
     │   &scope=openid%20email%20profile                      │
     │   &state=xyz789        ← anti-CSRF; echoed back        │
     │   &nonce=n-9f2c        ← anti-replay; bound into JWT  │
     │   &code_challenge=E9Melh...  ← SHA256(verifier)       │
     │   &code_challenge_method=S256                          │
     │                            │                           │
     │                            │── GET /authorize?… ──────►│
     │                            │                           │
```

**Harbor-HOT validates immediately (§11.7 — the open-redirect defense):**

```
    Harbor-HOT
         │
         │  ① client_id known?      NO  ──► HTML error page (no redirect ever) ──► stop
         │                                   ↑ critical: redirect_uri unproven yet
         │  ② redirect_uri exact match?
         │     (against registered allowlist) NO  ──► HTML error page (no redirect) ──► stop
         │
         │  ③  redirect target now proven trusted — safe to redirect errors from here on
         │
         │  ④ response_type = code?   NO  ──► 302 error=unsupported_response_type
         │  ⑤ scopes valid + includes openid?  NO  ──► 302 error=invalid_scope
         │  ⑥ code_challenge present + method=S256?  NO  ──► 302 error=invalid_request
         │  ⑦ state present?  NO  ──► 302 error=invalid_request
         │
         │  ✓ all pass → Harbor-HOT hands off to the login/consent UI
         │             (the authentication UI is cold-path; /authorize
         │              orchestration itself stays on the hot path — §4.1)
```
