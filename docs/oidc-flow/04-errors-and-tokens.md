> **OIDC Flow — Part 4 of 4** · [↑ Overview](../OIDC-LOGIN-FLOW.md) · prev: [03-token-exchange](03-token-exchange.md)

# OIDC Flow — Error Paths & What Makes Harbor's Tokens Different

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

- **Design index** — [`DESIGN.md`](../DESIGN.md): navigate to §11.7 (`design/flows/error-cases.md`) for error-path rationale, or §3.5 (`design/protocol/tokens.md`) for token lifecycle design.
- **As-built code + tests** — [`docs/features/oidc-authorization-code.md`](../features/oidc-authorization-code.md):
  the feature doc mapping the flow to `internal/oidc/`, `internal/oidcapi/`, and
  the security invariants in the test suite.
- **PPID derivation** — [`docs/features/ppid-identity.md`](../features/ppid-identity.md):
  the anti-tracking core (`DerivePPID`) that produces the per-RP `sub` at step 3.
- **Passkey ceremonies** — [`docs/features/webauthn-passkeys.md`](../features/webauthn-passkeys.md):
  the WebAuthn registration/login that drives Harbor-COLD's authentication step.
- **System overview** — [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md): the 10,000-ft
  map (hot/cold path, regions, KMS) before diving into this detail.
