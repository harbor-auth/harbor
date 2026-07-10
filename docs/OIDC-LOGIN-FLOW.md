# OIDC Login Flow — Authorization Code + PKCE

> A step-by-step walkthrough of Harbor's **most complex sequence** (DESIGN.md §11.2).
> The happy path first, then the error paths (§11.7), then what makes Harbor's
> tokens different.
>
> Read [`ARCHITECTURE.md`](ARCHITECTURE.md) for the system overview first, and
> [`DESIGN.md §11.2`](DESIGN.md) for the authoritative prose. This doc is the
> sequence-diagram companion — same content, drawn out, cross-referenced by step.

---

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

---

## Step 3 — Harbor Authenticates the User (the Harbor-specific part)

This step is **entirely on Harbor's UI** — the browser talks to Harbor-COLD:

```
    Browser                   Harbor-COLD                  Regional DB        Regional KMS
       │                           │                           │                   │
       │── show login screen ─────►│                           │                   │
       │                           │                           │                   │
       │   ┌─────────────────────────── passkey ceremony ──────────────────────┐   │
       │   │                       │                           │               │   │
       │   │◄── WebAuthn challenge ┤                           │               │   │
       │   │   (browser prompts    │                           │               │   │
       │   │    Touch ID / Face)   │                           │               │   │
       │   │── signed assertion ──►│                           │               │   │
       │   │   (phishing-resistant │── verify sig, clone ─────►│               │   │
       │   │    — §7.1)            │   detection               │               │   │
       │   │                       │◄── user record ───────────│               │   │
       │   └───────────────────────────────────────────────────────────────────┘   │
       │                           │                           │                   │
       │   ┌─────────────────── MFA step-up (if required) ────────────────────┐   │
       │   │◄── TOTP prompt ───────┤                           │               │   │
       │   │── TOTP code ─────────►│── verify TOTP secret ────►│               │   │
       │   └───────────────────────────────────────────────────────────────────┘   │
       │                           │                           │                   │
       │   ┌────────────────────────── consent screen ──────────────────────────┐  │
       │   │                       │                                             │  │
       │   │◄── "App X wants:      │                                             │  │
       │   │    • Your email       │  ← Harbor shows EXACTLY what the RP asked  │  │
       │   │      (relay address?) │                                             │  │
       │   │    • Your name"       │  ┌─ privacy options offered: ────────────┐ │  │
       │   │                       │  │  ✓ use relay email  x7f3@relay.eu.…   │ │  │
       │   │                       │  │    (hides real email from RP — §7.5)  │ │  │
       │   │── user approves ─────►│  └────────────────────────────────────────┘ │  │
       │   │                       │                                             │  │
       │   │                       │── record grant (pairwise_sub, scopes) ─────►│  │
       │   │                       │   derive PPID for this (user, RP) pair  ────┼──► decrypt
       │   │                       │   (§3.2 — per-user secret from DB)      ◄───┼── pairwise_secret
       │   └─────────────────────────────────────────────────────────────────────┘  │
```

**Key Harbor differences at this step:**

```
  ┌─── Privacy decisions made HERE (step 3) ────────────────────────────────┐
  │                                                                         │
  │  PPID sub:  same user → different sub at every RP  (§3.2)              │
  │             sub = B64URL( HMAC-SHA256( pairwise_secret,                 │
  │                                        sector || user_id ) )            │
  │             → RP-A and RP-B see unrelated subjects; can't correlate    │
  │                                                                         │
  │  Relay email:  x7f3q9a2@relay.eu.harbor.id  (§7.5)                    │
  │                → RP gets a unique, per-app disposable address           │
  │                → user's real email is never revealed by default         │
  │                → user can kill it per-app independently                 │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘
```

---

## Step 4 — Harbor Redirects Back with the Authorization Code

```
    Harbor-HOT                 Regional DB              Browser              RP
         │                         │                      │                   │
         │── generate code ────────►│                      │                   │
         │   (random, single-use,   │── store code ────────►│                   │
         │    ~60s TTL,             │   { code, client_id, │                   │
         │    binds client_id +     │     redirect_uri,    │                   │
         │    redirect_uri +        │     code_challenge,  │                   │
         │    code_challenge +      │     nonce, subject } │                   │
         │    nonce + subject)      │                      │                   │
         │                                                 │                   │
         │── 302 ─────────────────────────────────────────►│                   │
         │   Location: https://app.example.com/callback    │                   │
         │   ?code=SplxlOB...S6WxSbIA                      │                   │
         │   &state=xyz789   ← echoed verbatim (§11.7)     │                   │
         │                                                 │                   │
         │                                                 │── GET /callback? ►│
         │                                                 │   code&state      │
         │                                                 │                   │── verify state==stored ✓
         │                                                 │                   │   (CSRF check)
```

**The code is safe in the URL** because it's single-use and worthless without the
`code_verifier` (never sent in a redirect).

---

## Step 5 — RP Exchanges Code for Tokens (Back-channel)

```
    RP                                              Harbor-HOT              Regional DB / KMS
     │                                                  │                         │
     │── POST /token (back-channel, not via browser) ──►│                         │
     │   grant_type=authorization_code                  │                         │
     │   &code=SplxlOB...S6WxSbIA                       │                         │
     │   &redirect_uri=https://app.example.com/callback │                         │
     │   &client_id=rp_abc123                           │                         │
     │   &code_verifier=dBjftJeZ4CVP...bU3              │                         │
     │   (the ORIGINAL secret from step 1) ─────────────┼─────────────────────────┤
     │                                                  │                         │
     │                                 ┌── token validation sequence ─────────────┤
     │                                 │   (ordering is the DoS defense — §11.7) │
     │                                 │                                          │
     │                                 │ ① PEEK code (no mutation yet)           │
     │                                 │   ── not found → invalid_grant           │
     │                                 │   ── already consumed?                   │
     │                                 │      → THEFT SIGNAL → revoke family      │
     │                                 │      → invalid_grant                     │
     │                                 │                                          │
     │                                 │ ② VALIDATE (against stored code)         │
     │                                 │   ── client_id match?                    │
     │                                 │   ── redirect_uri match?                 │
     │                                 │   ── code not expired (~60s)?            │
     │                                 │   ── SHA256(code_verifier)==code_challenge│
     │                                 │      (constant-time compare — §11.7)     │
     │                                 │   any failure → invalid_grant (no burn!) │
     │                                 │                                          │
     │                                 │ ③ CONSUME (single-use tombstone)         │
     │                                 │   ── lost race → reuse → revoke + error  │
     │                                 │                                          │
     │                                 │ ④ MINT TOKENS                            │
     │                                 │   ── sign ID token (ES256) via KMS ─────►│
     │                                 │   ── sign access token (ES256) via KMS   │
     │                                 │   ── store opaque refresh token (hashed) │
     │                                 └──────────────────────────────────────────┤
     │                                                  │                         │
     │◄── 200 JSON ─────────────────────────────────────│                         │
     │    {                                             │                         │
     │      "token_type":    "Bearer",                  │                         │
     │      "expires_in":    600,                       │                         │
     │      "id_token":      "eyJhbGciOiJFUzI1Ni…",    │                         │
     │      "access_token":  "…",                       │                         │
     │      "refresh_token": "…"                        │                         │
     │    }                                             │                         │
     │    Cache-Control: no-store  (§11.7)              │                         │
```

---

## Step 6 — RP Validates the ID Token (JWT)

The RP verifies the JWT **offline** — no call back to Harbor required (§6.1):

```
    RP                                          Harbor-HOT (JWKS endpoint)
     │                                               │
     │── GET /jwks.json  (first time or new kid) ───►│  ← cached long TTL; edge/CDN (§6.1)
     │◄── { "keys": [{ "kid": "k1", "alg": "ES256",  │    one fetch; verify millions times
     │       "x": "…", "y": "…" }] }                 │
     │                                               │
     │  (all subsequent verifications are local — no network call)
     │  ┌── offline JWT verification ────────────────────────────────────────────┐
     │  │                                                                        │
     │  │  1. decode header → find "kid" → pick matching key from cached JWKS    │
     │  │  2. verify ES256 signature (public key only — private never leaves HSM)│
     │  │  3. check "iss" == "https://eu.harbor.id"    (region-scoped issuer)    │
     │  │  4. check "aud" == "rp_abc123"               (our client_id)           │
     │  │  5. check "exp" not passed                   (short TTL ~5–10 min)     │
     │  │  6. check "nonce" == the value from step 1   (anti-replay — §11.7)     │
     │  │                                                                        │
     │  └────────────────────────────────────────────────────────────────────────┘
     │
     │  Decoded payload:
     │  {
     │    "iss":            "https://eu.harbor.id",
     │    "sub":            "PPID_9f83a2…",        ← per-RP pairwise id (§3.2)
     │    "aud":            "rp_abc123",
     │    "exp":            1730000900,
     │    "iat":            1730000600,
     │    "nonce":          "n-9f2c",
     │    "email":          "x7f3@relay.eu.harbor.id",  ← relay, not real (§7.5)
     │    "email_verified": true,
     │    "name":           "Alex"                  ← only if user chose to share
     │  }
```

---

## Step 7 — RP Creates Its Own Session

```
    RP
     │
     │  read sub = "PPID_9f83a2…"
     │  look up / create local user record keyed by sub
     │  issue OWN session cookie (HttpOnly, Secure)
     │
     │  ← Harbor tokens are done; the app now has its own session
     │  ← "log out of Harbor" ≠ "log out of this app" (§11.3)
     │     (revoking the refresh token cuts future token refresh,
     │      but existing RP sessions remain until they expire)
```

---

## Step 8 — Token Refresh & Revocation (optional, ongoing)

```
    RP                                          Harbor-HOT              Regional DB
     │                                               │                      │
     │   (access token nearing expiry)               │                      │
     │                                               │                      │
     │── POST /token ────────────────────────────────►│                      │
     │   grant_type=refresh_token                    │── lookup + rotate ──►│
     │   &refresh_token=<opaque>                     │   refresh token       │
     │   &client_id=rp_abc123                        │   (one-time, reuse   │
     │                                               │    detection — §3.5) │
     │◄── new access_token + new refresh_token ───────│◄─ new token stored   │
     │                                               │                      │
     │   (user wants to disconnect this app)         │                      │
     │                                               │                      │
     │── POST /revoke ────────────────────────────────►│                      │
     │   token=<refresh_token>                       │── delete refresh ────►│
     │   &token_type_hint=refresh_token              │   tokens for grant    │
     │◄── 200 ────────────────────────────────────────│                      │
     │                                               │                      │
     │   result: no new access tokens can be minted; │                      │
     │   short-lived access tokens expire naturally  │                      │
     │   (or bloom-filter kill for emergency — §3.5) │                      │
```

---

## Error Paths (§11.7)

Two distinct error channels depending on *where* the problem is detected:

```
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │  CHANNEL A — /authorize errors that CAN redirect (redirect target is safe) │
  │                                                                             │
  │  302 → redirect_uri?error=<code>&error_description=<msg>&state=<echo>      │
  │                                                                             │
  │  ┌─────────────────────────────────────────────────────────────────────┐   │
  │  │  *** CRITICAL EXCEPTION — these NEVER redirect (no redirect_uri    │   │
  │  │  is proven yet):                                                    │   │
  │  │  • unknown client_id                                                │   │
  │  │  • missing / mismatched redirect_uri                               │   │
  │  │                                                                     │   │
  │  │  → render HTML error page in browser; no Location header           │   │
  │  └─────────────────────────────────────────────────────────────────────┘   │
  │                                                                             │
  │  Safe-to-redirect errors:                                                  │
  │  • unsupported_response_type  (not "code")                                 │
  │  • invalid_scope              (missing openid, unknown scope)              │
  │  • invalid_request            (missing PKCE/state/nonce, bad method)       │
  │  • unauthorized_client        (client policy)                              │
  │  • access_denied              (user hit "cancel" on consent screen)        │
  │  • login_required             (prompt=none, no session)                    │
  │  • consent_required / interaction_required  (prompt=none, consent needed)  │
  │  • server_error / temporarily_unavailable                                  │
  └─────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────┐
  │  CHANNEL B — /token errors (back-channel; RP reads JSON, no browser)       │
  │                                                                             │
  │  HTTP 400 (or 401 for client-auth failures) + JSON body:                   │
  │  { "error": "…", "error_description": "…" }                               │
  │  Cache-Control: no-store                                                    │
  │                                                                             │
  │  Key cases:                                                                 │
  │  • invalid_grant (400)   — expired code, PKCE mismatch, wrong client,      │
  │                             REUSED code (→ revoke family — theft signal)   │
  │  • invalid_client (401)  — bad client_secret                               │
  │  • unsupported_grant_type (400) — not authorization_code or refresh_token  │
  │  • invalid_request (400) — missing params                                  │
  │                                                                             │
  │  All token failures collapse to generic descriptions (§11.7):              │
  │  "Authorization code is invalid, expired, or already used" — never         │
  │  reveals WHICH check failed (no user/client existence disclosure).          │
  └─────────────────────────────────────────────────────────────────────────────┘
```

### Error flow example — PKCE mismatch at /token

```
    RP                              Harbor-HOT
     │                                  │
     │── POST /token                    │
     │   code_verifier=WRONG_VALUE ────►│
     │                                  │ PEEK ✓ (code exists, not reused)
     │                                  │ VALIDATE:
     │                                  │   SHA256(WRONG_VALUE) ≠ code_challenge
     │                                  │   → return error WITHOUT consuming the code
     │                                  │     (the code stays valid for the real owner)
     │◄── 400 ──────────────────────────│
     │   { "error": "invalid_grant",    │
     │     "error_description": "…" }   │
     │   Cache-Control: no-store        │
```

### Error flow example — code reuse (theft signal)

```
    RP (or attacker who stole the code)    Harbor-HOT              Regional DB
     │                                         │                       │
     │── POST /token (code already used) ─────►│                       │
     │                                         │ PEEK: already consumed!
     │                                         │── REVOKE code family ─►│ delete all tokens
     │                                         │   (assumes theft)      │ from this code's grants
     │◄── 400 invalid_grant ───────────────────│                        │
     │                                         │                        │
     │   result: even the legitimate RP is     │                        │
     │   forced to re-auth — reuse is always   │                        │
     │   treated as a compromise signal (§3.5) │                        │
```

---

## What Makes Harbor's Tokens Different

```
  Google ID token sub:  "117034977..."   ← stable per Google account
                                           same at App-A and App-B → trivial correlation

  Apple ID token sub:   "001234.abc..."  ← stable per developer TEAM
                                           same across all of one company's apps

  Harbor ID token sub:  "PPID_9f83a2…"  ← stable per RP REGISTRATION (sector)
                                           App-A sees one sub, App-B sees a DIFFERENT sub
                                           even for the same user at the same company
                                           unless they deliberately share a sector_identifier_uri

  Harbor email claim:   "x7f3@relay.eu.harbor.id"  ← per-app disposable relay address
                                                       real email is never shared by default
                                                       user can kill it per-app (§7.5)
```

**Token lifetimes and why:**

```
  ┌────────────────────────────────────────────────────────────────────┐
  │  authorization code    ~60 seconds, single-use                     │
  │  → safe in URL redirect; useless without code_verifier             │
  │                                                                    │
  │  access token (JWT)    ~5–15 minutes                               │
  │  → RP / resource server verifies offline via JWKS (no DB hit)      │
  │  → short TTL bounds exposure window if stolen                      │
  │                                                                    │
  │  refresh token (opaque) long-lived, rotating, one-time-use         │
  │  → DB-backed; revocation is instant; the real "off switch"         │
  │  → reuse detected → entire token family revoked (theft signal)     │
  │                                                                    │
  │  JWKS public keys       long TTL (hours), CDN-cached per kid       │
  │  → verification is purely local after first fetch (§6.1)           │
  │  → rotate with overlap: publish new kid, old tokens expire         │
  └────────────────────────────────────────────────────────────────────┘
```

---

## Full Happy-Path Summary

```
  RP                    Browser               Harbor-HOT     Harbor-COLD    DB / KMS
  │                        │                      │               │            │
  │ [Step 1]               │                      │               │            │
  │ generate verifier,     │                      │               │            │
  │ challenge, state,      │                      │               │            │
  │ nonce                  │                      │               │            │
  │                        │                      │               │            │
  │ [Step 2]               │                      │               │            │
  │──302 to /authorize────►│──GET /authorize?─────►│               │            │
  │                        │  …S256…              │               │            │
  │                        │                      │ validate      │            │
  │                        │                      │ client+URI    │            │
  │                        │◄─────────────────────│ hand off ────►│            │
  │                        │                      │               │            │
  │                        │ [Step 3]              │               │            │
  │                        │◄──passkey challenge───│               │            │
  │                        │──assertion───────────────────────────►│──verify───►│
  │                        │◄──consent screen──────────────────────│            │
  │                        │──approve─────────────────────────────►│─PPID──────►│
  │                        │                      │               │            │
  │                        │ [Step 4]              │               │            │
  │                        │◄─302 /callback?code──────────────────►│            │
  │◄──GET /callback?code───│  &state=xyz789        │               │            │
  │  verify state ✓         │                      │               │            │
  │                        │                      │               │            │
  │ [Step 5]               │                      │               │            │
  │──POST /token (back-channel)──────────────────►│──peek/validate/consume────►│
  │  code + code_verifier  │                      │──sign tokens (ES256) ─────►│(KMS)
  │◄──id_token + tokens────│──────────────────────│               │            │
  │                        │                      │               │            │
  │ [Step 6]               │                      │               │            │
  │──GET /jwks.json (once, cached)───────────────►│               │            │
  │◄──public keys──────────│──────────────────────│               │            │
  │ verify JWT offline ✓   │                      │               │            │
  │ (iss, aud, exp, nonce, │                      │               │            │
  │  sig — no Harbor call) │                      │               │            │
  │                        │                      │               │            │
  │ [Step 7]               │                      │               │            │
  │ create own session     │                      │               │            │
  │ keyed on PPID sub      │                      │               │            │
  ▼                        ▼                      ▼               ▼            ▼
```

---

## Where to Go Next

- **The authoritative prose** — [`DESIGN.md §11.2`](DESIGN.md): the full step-by-step
  walkthrough with rationale, including §11.7 (error cases) and §3.5 (token lifecycle).
- **As-built code + tests** — [`docs/features/oidc-authorization-code.md`](features/oidc-authorization-code.md):
  the feature doc mapping the flow to `internal/oidc/`, `internal/oidcapi/`, and
  the security invariants in the test suite.
- **PPID derivation** — [`docs/features/ppid-identity.md`](features/ppid-identity.md):
  the anti-tracking core (`DerivePPID`) that produces the per-RP `sub` at step 3.
- **Passkey ceremonies** — [`docs/features/webauthn-passkeys.md`](features/webauthn-passkeys.md):
  the WebAuthn registration/login that drives Harbor-COLD's authentication step.
- **System overview** — [`docs/ARCHITECTURE.md`](ARCHITECTURE.md): the 10,000-ft
  map (hot/cold path, regions, KMS) before diving into this detail.
