# Proposal: Discoverable Login (replace devUserResolver)

**Change ID:** discoverable-login-0ad35f86
**Status:** draft
**Design refs:** §3.1, §6.5, §9, §11.1

## Problem

`devUserResolver` in `cmd/harbor-mgmt/bff.go` reads a `?user_id` query
parameter to identify the user before the passkey assertion. This is an
unshippable dev scaffold:

1. Real users cannot supply a Harbor-internal user handle — there is no
   client-visible path to obtain one.
2. An email→user_id lookup is impossible by design — the `users` table stores
   no email column (§6.5, privacy model).
3. Pre-identifying the user before the ceremony is unnecessary for passkeys:
   WebAuthn discoverable credentials return the `userHandle` from the
   authenticator in the assertion response.

## Proposed Change

Replace `devUserResolver` with **WebAuthn discoverable credentials** (passkey
autofill / conditional UI):

- `BeginDiscoverableLogin` — RP sends an assertion challenge with no
  `allowCredentials` and no pre-specified user. The browser presents stored
  passkeys via its autofill UI.
- `FinishDiscoverableLogin` — the authenticator response carries `userHandle`;
  the service resolves the user via `store.GetUser(ctx, userHandle)` and runs
  the normal clone-detection + signature validation.

No DB changes. No new queries. No email lookup. Identification is fully
delegated to the authenticator.

## Non-goals

- Frontend conditional-UI (`mediation: 'conditional'`) implementation.
- Multi-factor / step-up login path changes.
- Any modification to the users table schema.
- Non-discoverable (multi-factor) login path — it is removed, not extended.
