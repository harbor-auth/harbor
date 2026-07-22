# Proposal: Consent management UI (user privacy dashboard)

## Problem

Harbor's core promise is that **the user, not the operator, controls what each
RP learns** (§2.1). The substrate exists — `consent-ledger` ✅ persists
per-(user, RP) grants and can revoke them, and `user-audit-trail` records the
user's own history — but there is **no user-facing surface** to see and exercise
that control. A privacy promise the user cannot inspect or act on is not a
realised promise. Users need one place to answer: *which apps can see my data,
what did I grant each one, what have they done, and how do I cut one off?*

## Proposed Solution

1. **Connected-apps (grants) view** — list the signed-in user's `consent_grants`
   (scopes, granted-at, last-used) from the `consent-ledger` read endpoint.
2. **Revoke-app action** — call the shipped consent-revoke, which already
   cascades an RP token/session revocation; reflect the change in the view.
3. **Activity (audit-trail) view** — render the user's **own decrypted**
   `user-audit-trail` events; decrypt only under the caller's DEK — no operator
   plaintext path, strictly the caller's own events.
4. **Sessions & devices** — list and revoke active sessions / registered
   authenticators (reuse the shipped session + WebAuthn stores).
5. **Soft per-RP email-relay toggle** — surface `email-relay-service` per-RP when
   present; absent/disabled (feature-detected) when relay isn't deployed — no
   hard dependency.
6. **Privacy-safe composition** — a thin composition over existing user-scoped
   endpoints; region-pinned reads only; aggregate-only UI metrics.

## Non-Goals

- **No new data store** and **no new authorization primitives** — pure
  composition over shipped user-scoped endpoints.
- **No cross-user / admin-ish read path** — the dashboard is strictly
  caller-scoped.
- **No operator plaintext path** to the user's activity — the activity view
  decrypts under the caller's DEK only.
- **No hard dependency on `email-relay-service`** — the relay toggle is soft and
  feature-detected.

## Success Criteria

- [ ] A signed-in user sees only their **own** connected apps, activity, and sessions.
- [ ] Revoking an app calls the shipped consent-revoke and **cascades** the RP token/session revocation; the view reflects it.
- [ ] The activity view decrypts under the **caller's DEK only**; no operator plaintext path; no cross-user leak.
- [ ] The per-RP relay toggle is present when `email-relay-service` is live and **degrades gracefully** when it isn't.
- [ ] Reads are region-pinned; UI metrics are aggregate-only; no PII in client logs/analytics.
- [ ] `make agent-check` clean.
