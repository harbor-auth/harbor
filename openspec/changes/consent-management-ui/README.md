# consent-management-ui

Give the user a place to actually **see and exercise** the control Harbor
promises (§2.1): a user-authenticated **privacy dashboard** on the BFF, composed
entirely from already-shipped user-scoped primitives — **no new data store, no
new authorization model**. A **connected-apps** view lists the caller's
`consent_grants` (scopes, granted-at, last-used) from `consent-ledger` ✅, with a
**revoke** action that calls the shipped consent-revoke (which cascades an RP
token/session revocation). An **activity** view renders the caller's **own
decrypted** `user-audit-trail` events — decrypted only under the caller's DEK,
with **no operator plaintext path** and strictly caller-scoped. A **sessions &
devices** view lists and revokes active sessions / registered authenticators. A
**soft, feature-detected per-RP email-relay toggle** surfaces
`email-relay-service` when it's live and degrades gracefully when it isn't. Reads
are **region-pinned** and UI metrics are **aggregate-only** (no PII in client
logs/analytics).
