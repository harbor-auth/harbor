# Proposal: Consent ledger (per-user / per-RP / per-scope consent grants)

## Problem

User **consent** — the record that a given user has authorised a given RP for a
given set of scopes — is a stated privacy promise (§2.1: the user, not the
operator, controls what each RP may learn) with **zero shipped work**. Today the
`/authorize` flow has no durable notion of prior consent: it cannot skip the
consent prompt for an already-authorised `(user, RP, scope)` tuple, and — more
seriously — it has no basis to **force re-consent when an RP escalates the
requested scopes**. There is also no user-facing way to see or revoke what a
user has granted. The consent ledger is the **substrate** the user dashboard and
the `user-audit-trail` both need.

## Proposed Solution

1. **Data model (`0011_consent_grants`)** — a `consent_grants` table keyed by
   `(user_id, client_id)` with the **granted scope set** (normalised: sorted,
   canonical), `granted_at`, `updated_at`, and a nullable `revoked_at`. No PII
   beyond the `user_id`/`client_id` FKs and the scope strings — the row is
   authorisation metadata, not user content.
2. **Enforcement at `/authorize` (`internal/oidc/`)** — look up the
   `(user_id, client_id)` grant:
   - **No grant, or scopes escalate** (requested ⊄ granted) → present the
     consent ceremony; on approval **upsert** the grant with the widened set.
   - **Valid grant covering the requested scopes** → **skip** the prompt,
     subject to a `prompt=consent` override that always forces re-consent.
   - **Revoked grant** (`revoked_at` set) → treat as no grant (re-prompt).
   - Honour `prompt=none` per OIDC (error if consent would be required).
3. **Management surface (`internal/mgmtapi/`)** — cold-path, user-authenticated
   endpoints to **list** a user's consent grants and **revoke** one
   (`revoked_at`). Revocation cascades a session/token revocation for that RP
   (reuse the shipped revocation stack) so "withdraw consent" actually logs the
   RP out.
4. **Event emission (taxonomy for `user-audit-trail`)** — every grant / update /
   revoke emits a structured consent event (`consent.granted`,
   `consent.scope_escalated`, `consent.revoked`) through a small seam the
   `user-audit-trail` will consume.

## Non-Goals

- Building the durable per-user audit trail itself (that is `user-audit-trail`);
  this change only defines and emits the consent event taxonomy.
- Full OIDC `prompt` semantics beyond the consent decision — this change covers
  `prompt=consent` / `prompt=none`; `login` / `select_account` stay with the
  existing login flow.
- Per-user encryption of the scope set (the row is authorisation metadata, not
  content) — the envelope seam is available if that requirement later appears.
- Any cross-region consent lookup — consent lives with the user's regional row.

## Success Criteria

- [ ] `consent_grants` table (migration 0011) keyed `(user_id, client_id)` with granted scopes, `granted_at`, `updated_at`, `revoked_at`; unique `(user_id, client_id)`; FKs to users + clients.
- [ ] `/authorize` **skips** the prompt when a valid grant covers the requested scopes.
- [ ] `/authorize` **re-prompts** on no-grant, on scope escalation (requested ⊄ granted), and on a revoked grant; approval **upserts** the widened scope set.
- [ ] `prompt=consent` always forces re-consent; `prompt=none` errors when consent would be required (OIDC).
- [ ] Scope sets are canonicalised so the superset/escalation check is exact.
- [ ] Users can **list** their own grants and **revoke** one via `harbor-mgmt`; revoke sets `revoked_at` **and** cascades an RP token/session revocation.
- [ ] Consent events (`consent.granted`, `consent.scope_escalated`, `consent.revoked`) are emitted via a seam `user-audit-trail` can consume.
- [ ] No cross-user or cross-client grant leakage; no PII beyond FKs + scope strings.
- [ ] `make agent-check` clean.
