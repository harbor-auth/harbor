> **DESIGN §7.1–7.4** · [↑ DESIGN index](../../DESIGN.md) · next: [email-relay](email-relay.md)

# Security Design

## 7.1 Passkeys / MFA

- **Passkeys (WebAuthn) are primary.** Phishing-resistant, no shared secret. Support platform + roaming authenticators; encourage 2+ passkeys per account.
- **TOTP** as a secondary/step-up factor for users without passkeys.
- **Step-up auth** for sensitive operations (adding a passkey, changing recovery, connecting a high-trust RP).

## 7.2 Account recovery (the hardest problem) — recommendation

A privacy-first product **cannot** have a simple "email a reset link" backdoor (it's the #1 ATO vector and undermines the security story). Recommended layered approach, **user picks at least two**:

1. **Multiple passkeys** (encouraged default) — losing one device ≠ lockout.
2. **One-time recovery codes** — generated at enrollment, shown once, stored **hashed**; user keeps them offline.
3. **Hardware security key** as a dedicated recovery authenticator.
4. **(Opt-in) Social recovery** — user designates M-of-N trusted guardians who jointly approve recovery; no single party (including us) can recover alone.

We **never** unilaterally reset an account. Recovery requires **possession + knowledge** the user pre-registered. This is a deliberate, communicated trade-off: stronger security, so recovery must be set up in advance.

## 7.3 Key management

- **Regional KMS/HSM** holds KEKs and token-**signing** keys. Signing keys are asymmetric (ES256/EdDSA); private key never leaves the HSM boundary.
- **Rotation with overlap**: publish new `kid` in JWKS, sign new tokens with it, keep old public key until all old tokens expire.
- **Per-user DEKs** wrapped by regional KEK; enables crypto-shred.

## 7.4 Secure defaults

- PKCE mandatory, exact redirect-URI matching, `state`/`nonce` enforced.
- Argon2id for any passwords; short token TTLs; rotating one-time refresh tokens with reuse-detection.
- Strict CSP, HSTS, secure cookies (`HttpOnly`, `SameSite`), no third-party scripts in auth UI.
