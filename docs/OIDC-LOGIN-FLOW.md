# OIDC Login Flow — Authorization Code + PKCE

> Harbor's **most complex sequence** (DESIGN.md §11.2), drawn out as step-by-step
> ASCII sequence diagrams: the happy path first, then the error paths (§11.7),
> then what makes Harbor's tokens different. The detail now lives in a small
> tree of files under [`oidc-flow/`](oidc-flow/) — start here, then read in order.

## Reading order

1. [Part 1 — Registration, PKCE Setup & `/authorize`](oidc-flow/01-request-setup.md) — participants, RP registration, PKCE setup, and the `/authorize` open-redirect validation ladder.
2. [Part 2 — Authentication, Consent & Code Issuance](oidc-flow/02-authenticate.md) — passkey ceremony, MFA step-up, the consent screen (relay email + PPID), and the code redirect.
3. [Part 3 — Token Exchange, JWT Verification & Session](oidc-flow/03-token-exchange.md) — the back-channel `/token` exchange (peek→validate→consume), offline JWT verification, session creation, and refresh/revoke.
4. [Part 4 — Error Paths & Token Differences](oidc-flow/04-errors-and-tokens.md) — the two error channels, PKCE mismatch, code reuse (theft signal), and what makes Harbor's tokens different.

## Participants at a glance

| Participant | Role |
|---|---|
| **RP** | The third-party app (server-side): builds the request, exchanges the code, verifies the token. |
| **Browser** | Routes redirects between RP and Harbor; runs the WebAuthn passkey ceremony. |
| **Harbor-HOT** | Stateless hot path: validates `/authorize`, issues the code, handles the `/token` exchange. |
| **Harbor-COLD** | The login/consent UI: passkey auth, MFA step-up, consent (relay email + PPID). |
| **Regional DB** | Postgres/Redis — auth codes, client registry, grants, pairwise secrets. Never leaves the region. |
| **Regional KMS** | HSM-backed signing keys (ES256/EdDSA). Private keys never leave the HSM boundary. |

## Key Harbor differences

- **PKCE is mandatory** for every client (OAuth 2.1) — not just recommended.
- **`sub` is a per-RP PPID** (§3.2) — the same user gets an unrelated subject at each RP.
- **`email` is a relay address by default** (§7.5) — the real email is never shared unless the user opts in.
- **Passkey-first** authentication (§7.1) — phishing-resistant by design.
- **Per-jurisdiction issuer** (`eu.`/`us.`…, §5) — tokens are minted in, and data stays in, the user's region.

## Where to go next

- **System overview** — [`ARCHITECTURE.md`](ARCHITECTURE.md): the 10,000-ft map (hot/cold path, regions, KMS).
- **The authoritative design** — [`DESIGN.md`](DESIGN.md): the design index; §11.2 (flow), §11.7 (errors), §3.5 (token lifecycle).
- **As-built code + tests** — [`features/oidc-authorization-code.md`](features/oidc-authorization-code.md): the flow mapped to `internal/oidc/` and `internal/oidcapi/`.
- **PPID derivation** — [`features/ppid-identity.md`](features/ppid-identity.md): the anti-tracking core that produces the per-RP `sub`.
