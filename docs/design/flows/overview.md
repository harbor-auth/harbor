> **DESIGN §11.1, 11.3–11.6** · [↑ DESIGN index](../../DESIGN.md) · next: [error-cases](error-cases.md)

# Key User Flows

## 11.1 Passkey registration (enrollment)
1. On the home region's signup page, enter an email. `POST /enroll` sends an eight-digit verification code without creating an account.
2. Verify the code in the same browser with `POST /enroll/verify`. The server consumes the challenge, atomically creates a pending account and encrypted verified email identifier, then issues the first-passkey enrollment session.
3. Browser calls WebAuthn `create()`. The passkey shows the verified email as its account label; its opaque user handle still identifies the stable account UUID. Credential creation activates the pending account atomically.
4. Save and acknowledge recovery codes before full account access. Additional passkeys remain attached to the same account.
5. Continue to the validated return destination.

Email verification cannot sign in, recover, or add a passkey to an existing account. A verified duplicate is directed to passkey sign-in. There are no preexisting users or email-free public signup compatibility requirements. Email is the first typed account identifier; phone-number identifiers may follow without changing the account model. See [email-first signup](../../features/email-first-signup.md) for expiry, duplicate handling, encryption, and operational requirements.

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
