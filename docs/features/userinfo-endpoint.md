---
title: UserInfo Endpoint (OIDC Core §5.3 — GET /userinfo)
status: implemented
design_refs: [§3.3, §11.4, §3.1]
code:  [internal/oidcapi/, api/openapi/harbor.yaml, internal/gen/openapi/]
spec:  [api/openapi/harbor.yaml]
tests: [internal/oidcapi/]
depends_on: [real-token-issuance, user-enrollment]
plan: userinfo-endpoint
last_reconciled: 2026-11-03
---

# UserInfo endpoint

`GET /userinfo` returns `sub` and optional, explicitly consented personal claims.
ID tokens remain authentication-only. Use `(iss, sub)` as the website's identity
key. Email is contact information and a possible account-recovery hint; it is
never an account-linking credential.

| Scope | Result |
| --- | --- |
| `openid` | Stable pairwise `sub` for this app. |
| `email` | Verified **real** `email` and `email_verified: true`, after explicit consent. Both are omitted when the account has no verified email identifier. |
| `offline_access` | Rotating refresh token from the token endpoint. No extra UserInfo fields. |

`profile`, `phone`, `address`, and the optional OIDC `claims` parameter are not
implemented or advertised. Add a scope only alongside collected, maintained
data, precise consent wording, and disclosure tests. No dynamic claim registry
or generic profile storage is required.

## Disclosure boundary

The handler verifies the regional issuer, ES256 signature, access-token type,
expiry, emergency revocation and `openid` scope. It then checks the live client,
the exact active `grant_id`, the app-specific subject, active account status and
home region. Email is returned only in the intersection of the access token's
scope, live explicit consent and current app configuration. Decryption uses the
existing verified account identifier and user DEK. Missing consent or identifier
never produces an invented relay address or unverified email.

Invalid authorization returns `401 invalid_token`. Missing infrastructure or a
store/KMS outage returns `503`; no personal claims are returned. All responses
are `no-store`. Browser clients can use credentialless CORS with the Bearer
header; Harbor cookies are not used for UserInfo authorization.

## Grant lifetime

Canonical `grants` are the only authorization authority. Authentication/subject
resolution cannot approve scopes. Explicit approval atomically merges scopes
without replacing an active grant. Disconnect revokes the grant and bound
refresh sessions; reconnect creates a fresh grant ID and preserves the PPID.
Codes, access tokens, logout hints and refresh sessions bind that exact lifetime.
Old tokens cannot follow or revoke a replacement connection. Introspection
reports disconnected tokens inactive.

Refresh sessions persist the original approved scope ceiling and can only lose
permissions. Later consent cannot add email to an old token or refresh family.
Revocation prevents future disclosure; it cannot erase data already given to an
application or terminate that website's own login session.

## Upgrade behavior

Migration 0027 defaults `email_consent` to false. Older consent described a
private relay address; it does not authorize sharing the real address. A request
for `email` requires the new explicit consent, including with `prompt=none`.
Unbound legacy codes/access/logout tokens and refresh sessions with no scope
ceiling cannot act on a new grant. Users may need to sign in again after rollout.
Deploy the migration before the new binaries. Rollback refuses to delete grant
history to restore the old unconditional uniqueness constraint.

## Validation and integration

`internal/clients/scoped_userinfo_integration_test.go` uses actual migrations,
PostgreSQL, Redis codes, PPID derivation, encrypted identifiers, JWT issuance and
HTTP UserInfo. It covers real-email consent, old relay consent, no-email accounts,
concurrent approval, refresh ceilings, regional/account denial, revocation and
reconnection. HTTP unit tests cover malformed tokens and browser CORS.

See [account linking](../guides/account-linking.md) for a complete website-owned
migration flow and database reference. See OIDC Core
[scope claims](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)
and [claim stability](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability).
