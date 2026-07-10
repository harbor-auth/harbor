> **OIDC Flow — Part 2 of 4** · [↑ Overview](../OIDC-LOGIN-FLOW.md) · prev: [01-request-setup](01-request-setup.md) · next: [03-token-exchange](03-token-exchange.md)

# OIDC Flow — Authentication, Consent & Code Issuance

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
