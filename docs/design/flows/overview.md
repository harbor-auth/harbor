> **DESIGN §11.1, 11.3–11.6** · [↑ DESIGN index](../../DESIGN.md) · next: [error-cases](error-cases.md)

# Key User Flows

## 11.1 Passkey registration (enrollment)
1. User creates account in their home region (region chosen at signup, encoded in id).
2. Browser calls WebAuthn `create()`; Harbor stores the passkey public key + metadata.
3. User is prompted to set up **recovery** (≥2 methods) and optionally a 2nd passkey/TOTP.
4. `pairwise_secret` and DEK generated, wrapped by regional KEK, stored 🔒.

> **Note:** The OIDC login flow (§11.2) — the full Authorization Code + PKCE walkthrough — is documented in detail at [docs/OIDC-LOGIN-FLOW.md](../../OIDC-LOGIN-FLOW.md).

## 11.3 Add / remove a connected app
- Add: happens implicitly via first consent (§11.2, step 3 — the consent screen).
- Remove: dashboard → revoke grant → future logins require fresh consent; existing refresh tokens revoked; short-lived access tokens expire naturally (or bloom-filter kill).

## 11.4 MFA setup & step-up
- Setup: enroll TOTP or additional passkey in dashboard.
- Step-up: sensitive actions (edit recovery, connect high-trust RP) force a fresh strong assertion.

## 11.5 Account recovery
- User initiates recovery → must satisfy pre-registered methods (§7.2): e.g., a recovery code **+** a second passkey, or M-of-N social guardians. No unilateral operator reset.

## 11.6 GDPR view / export / delete
- **View/Export**: dashboard exports account data + audit log (JSON).
- **Delete**: destroy the user DEK (**crypto-shred**) → data unrecoverable even in backups; audit retains only minimal, legally-required, non-identifying records for the mandated window, then purged.
