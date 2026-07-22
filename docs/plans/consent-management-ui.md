---
title: Consent management UI (user privacy dashboard — grants, sessions, audit)
status: draft
design_refs: [§2.1, §11.4, §9]
targets: [internal/bff/, internal/mgmtapi/, web/]
promoted_to: null
openspec: changes/consent-management-ui
created: 2026-07-22
---

# Consent management UI (plan)

> **Dependency order:** **Gate 3** of Wave 5 — depends on the shipped
> `consent-ledger` ✅ (grants list/revoke + event taxonomy) and
> `user-audit-trail` (the decrypted, user-owned event history), and surfaces the
> per-RP **email-relay** toggle from `email-relay-service` (soft — the toggle
> degrades gracefully if relay isn't live yet). Builds on the shipped
> `bff-session-middleware` ✅ for the authenticated user session. Lands after
> Gate-1 guardrails and Gate-2 recovery; it is **read/allow-list surface only**
> — no new authorization primitives.

## Problem

Harbor's core promise is that **the user, not the operator, controls what each RP
learns** (§2.1). The substrate exists — `consent-ledger` persists per-(user, RP)
grants and can revoke them, and `user-audit-trail` records the user's own
history — but there is **no user-facing surface** to actually see and exercise
that control. A privacy promise the user cannot inspect or act on is not a
realised promise. Users need one place to answer: *which apps can see my data,
what exactly did I grant each one, what have they done, and how do I cut one
off?*

## Proposed approach

A user-authenticated **privacy dashboard** served by the BFF, composed entirely
from already-shipped read/revoke primitives.

1. **Connected apps (grants) view** — list the signed-in user's
   `consent_grants` (per RP: granted scopes, granted-at, last-used), reading the
   `consent-ledger` list endpoint. **Revoke** an app calls the shipped
   consent-revoke (which already cascades an RP token/session revocation).
2. **Activity view (audit trail)** — render the user's **own decrypted**
   `user-audit-trail` events (logins, token issue/refresh/revoke, consent
   changes), reading the user-only decrypted endpoint. Operator has no plaintext
   path; the UI only ever shows the caller their own events.
3. **Sessions & devices** — list active sessions / registered authenticators
   and allow the user to revoke a session or a device (reuse the shipped session
   + WebAuthn stores).
4. **Per-RP email-relay toggle (soft)** — where `email-relay-service` is live,
   expose a per-RP "hide my email" toggle wired to the relay lifecycle; when
   relay isn't deployed the toggle is absent/disabled — no hard dependency.
5. **Privacy-safe by construction** — the dashboard is a thin composition over
   existing user-scoped endpoints; it introduces **no** new data store, does
   region-pinned reads only, and emits only aggregate-only UI metrics.

## DESIGN alignment

Realises §2.1 (user-controlled consent — now inspectable and revocable by the
user), §11.4 (the user data surface / self-service), and §9 (the BFF is the
user-facing edge). Does **not** change `DESIGN.md` — it is the missing UI over
primitives the design already mandates. Introduces no new authorization model.

## Target code paths

- `internal/bff/dashboard.go` — authenticated dashboard handlers (connected
  apps, activity, sessions, relay toggle), composing shipped endpoints.
- `internal/mgmtapi/` — reuse the shipped consent list/revoke, audit-trail read,
  session/device revoke (add thin read aggregation only if needed).
- `web/` — dashboard templates/assets (server-rendered via the BFF; minimal,
  no PII in client logs/analytics).

## Implementation checklist

- [ ] BFF authenticated dashboard route(s) gated by the shipped session middleware; region-pinned reads.
- [ ] Connected-apps view: list the user's consent grants (scopes, granted-at, last-used) from `consent-ledger`.
- [ ] Revoke-app action: call the shipped consent-revoke (cascades RP token/session revocation); reflect the change.
- [ ] Activity view: render the user's **own decrypted** `user-audit-trail` events; no operator plaintext path; strictly the caller's own events.
- [ ] Sessions & devices view: list + revoke active sessions / registered authenticators (reuse shipped stores).
- [ ] Per-RP email-relay toggle wired to `email-relay-service` when present; gracefully absent/disabled when relay isn't deployed.
- [ ] UI metrics are aggregate-only (via `observability-metrics`); no PII in client logs/analytics.
- [ ] Tests: a user sees only their own grants/activity/sessions; revoking an app cascades the RP revocation and updates the view; another user's data is never exposed; the relay toggle degrades gracefully when relay is absent.
- [ ] Tests (security): the activity view decrypts under the caller's DEK only; no cross-user leakage; operator has no plaintext read path via the UI.
- [ ] Author & verify paired OpenSpec change: `openspec validate consent-management-ui --strict`
- [ ] Reconcile & promote: `@plan promote consent-management-ui`

## Risks & open questions

- **Composition, not new authority** — the dashboard must be a pure composition
  over existing user-scoped, region-pinned endpoints. Any temptation to add a
  new "admin-ish" read path that sees across users is a design violation — keep
  it strictly caller-scoped.
- **Audit-trail dependency ordering** — the activity view needs
  `user-audit-trail`'s decrypted read endpoint; if that lands after this UI,
  ship the connected-apps + sessions views first and gate the activity view
  behind the audit-trail endpoint's availability.
- **XSS / template safety** — rendering user- and RP-supplied strings (app
  names, scopes) must be contextually escaped; no user content is trusted.
- **Relay toggle coupling** — keep the toggle a soft, feature-detected element
  so this UI can ship even if `email-relay-service` lands later.

## Definition of done

`go build/vet/test ./...` green; a signed-in user can see their connected apps
(with granted scopes), revoke an app (cascading the RP revocation), review their
own decrypted activity, and manage sessions/devices — all strictly
caller-scoped, region-pinned, and with no operator plaintext path; the per-RP
relay toggle is present when relay is live and gracefully absent otherwise; UI
metrics are aggregate-only; `make agent-check` clean. Ready to `@plan promote`.
