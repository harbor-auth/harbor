> **OIDC Flow — Part 3 of 4** · [↑ Overview](../OIDC-LOGIN-FLOW.md) · prev: [02-authenticate](02-authenticate.md) · next: [04-errors-and-tokens](04-errors-and-tokens.md)

# OIDC Flow — Token Exchange, JWT Verification & Session

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
