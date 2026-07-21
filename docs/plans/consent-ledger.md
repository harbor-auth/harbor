---
title: Consent ledger (per-user / per-RP / per-scope consent grants)
status: completed
design_refs: [§2.1, §10, §11.3]
targets: [internal/oidc/, internal/mgmtapi/, internal/clients/, db/migrations/, db/queries/]
promoted_to: null
openspec: changes/consent-ledger
created: 2026-07-21
---

# Consent ledger (plan)

> **Dependency order:** a **root** — no hard prerequisites. It reuses the
> shipped client registry (`client-grant-persistence`) and PPID/session seams,
> but adds an independent, cold-path table and does not touch the hot-path
> router. `user-audit-trail` is **soft-gated** on this plan's event taxonomy
> (consent grant/revoke events feed the trail), but this plan stands alone.
>
> **Migration prefix `0011` is reserved** for this plan
> (`db/migrations/0011_consent_grants.up.sql` / `.down.sql`). Do not reuse
> `0011` in any other in-flight plan — the historical migration-collision
> failure mode (multiple branches grabbing the same `NNNN_` prefix) is exactly
> what this reservation prevents.

## Problem

User **consent** — the record that a given user has authorised a given RP for a
given set of scopes — is a stated privacy promise (§2.1: the user, not the
operator, controls what each RP may learn) with **zero shipped work**. Today the
`/authorize` flow has no durable notion of prior consent: it cannot skip the
consent prompt for an already-authorised (user, RP, scope) tuple, and — more
seriously — it has no basis to **force re-consent when an RP escalates the
requested scopes**. There is also no user-facing way to see or revoke what
they've granted. The consent ledger is the **substrate** the user dashboard and
the `user-audit-trail` both need.

## Proposed approach

1. **Data model (`0011_consent_grants`)** — a `consent_grants` table keyed by
   `(user_id, client_id)` with the **granted scope set**, `granted_at`,
   `updated_at`, and a nullable `revoked_at`. Scopes are stored as a normalised
   set (sorted, canonical) so escalation is a set-superset check. No PII beyond
   the `user_id`/`client_id` FKs and the scope strings; the row is *authorisation
   metadata*, not user content. (If per-user encryption of the scope set is
   later required it can reuse the envelope seam — noted, not built here.)
2. **Enforcement at `/authorize` (`internal/oidc/`)** — on an authorization
   request, look up the `(user_id, client_id)` grant:
   - **No grant, or scopes escalate** (requested ⊄ granted) → present the
     consent ceremony; on approval, **upsert** the grant with the (possibly
     widened) scope set.
   - **Valid grant covering the requested scopes** → **skip** the prompt
     (frictionless re-login), subject to a configurable
     `prompt=consent` override that always forces re-consent (OIDC
     `prompt` param compliance).
   - **Revoked grant** (`revoked_at` set) → treat as no grant (re-prompt).
3. **Management surface (`internal/mgmtapi/`)** — cold-path, user-authenticated
   endpoints to **list** a user's consent grants and **revoke** one
   (`revoked_at`). Revocation here is the user pulling authorisation from an RP;
   it SHOULD also cascade to a session/token revocation for that RP (reuse the
   shipped revocation stack) so "withdraw consent" actually logs the RP out.
4. **Event emission (taxonomy for `user-audit-trail`)** — every grant / update /
   revoke emits a structured consent event (`consent.granted`,
   `consent.scope_escalated`, `consent.revoked`) through a small seam that
   `user-audit-trail` will consume. Define the event shape here; the durable
   per-user trail is the other plan's job.

**Alternatives considered.** *Infer consent from the presence of a session /
refresh token* — rejected: a session is authentication state, not a durable,
revocable authorisation record; it can't express "granted `email` but not
`profile`" or survive re-login. *Store consent inside the client registry row* —
rejected: consent is per-(user, client), not per-client; it belongs in its own
table keyed by both. *Prompt on every login* — rejected: defeats the
frictionless-SSO goal and trains users to click through consent blindly.

## DESIGN alignment

Realises §2.1 (user-controlled authorisation — the user decides what each RP
learns), §10 (a new data-model table, encrypted/minimised per the 🔒 discipline
where applicable), and §11.3 (the authorization/consent flow). It does **not**
change `DESIGN.md` — user consent is already a stated pillar; this plan builds
the missing persistence and enforcement. Consent state is **regional** (lives
with the user's row in their home jurisdiction) — no cross-region consent
lookup, consistent with §5.

## Target code paths

- `db/migrations/0011_consent_grants.up.sql` / `.down.sql` — the
  `consent_grants` table (**reserved prefix 0011**).
- `db/queries/consent_grants.sql` — sqlc queries (upsert, get-by-user-client,
  list-by-user, revoke).
- `internal/clients/consent.go` — `ConsentStore` (get / upsert / list / revoke)
  over the generated queries.
- `internal/oidc/` — `/authorize` enforcement: consult the ledger, decide
  skip-vs-prompt, upsert on approval, honour `prompt=consent`.
- `internal/mgmtapi/` — user-facing list/revoke consent endpoints.

## Implementation checklist

- [ ] Migration `0011_consent_grants` (up/down): `consent_grants(user_id, client_id, scopes, granted_at, updated_at, revoked_at)`, unique `(user_id, client_id)`, FKs to users + clients. **Prefix 0011 is reserved for this plan.**
- [ ] `db/queries/consent_grants.sql` + `make codegen` (sqlc): upsert-grant, get-by-user-client, list-by-user, revoke.
- [ ] `internal/clients/consent.go`: `ConsentStore` with get / upsert / list / revoke; compile-time interface assertion.
- [ ] `/authorize` enforcement (`internal/oidc/`): skip prompt when a valid grant covers requested scopes; prompt + upsert on no-grant or scope escalation (requested ⊄ granted); treat `revoked_at` as no grant; honour `prompt=consent` (force) and `prompt=none` (error if consent required, per OIDC).
- [ ] Scope-set canonicalisation (sorted/deduped) so superset/escalation checks are exact.
- [ ] `internal/mgmtapi/` user endpoints: list my consent grants; revoke a grant (sets `revoked_at`) and cascade a token/session revocation for that RP via the shipped revocation stack.
- [ ] Emit structured consent events (`consent.granted`, `consent.scope_escalated`, `consent.revoked`) via a seam `user-audit-trail` can consume; define the event schema.
- [ ] Tests: first authorize prompts + persists grant; repeat authorize with subset scopes skips prompt; scope escalation re-prompts + widens the grant; `prompt=consent` always re-prompts; revoked grant re-prompts; revoke endpoint sets `revoked_at` + cascades RP token revocation.
- [ ] Tests (security/privacy): no cross-user or cross-client grant leakage (a user only sees/revokes their own grants; a grant only satisfies its own `client_id`); no PII beyond FKs + scope strings in the row.
- [ ] Author & verify paired OpenSpec change: `openspec validate consent-ledger --strict`
- [ ] Reconcile & promote: `@plan promote consent-ledger`

## Risks & open questions

- **Migration-number collision** — **0011 is reserved**; any parallel plan
  adding a migration must take a different prefix. This is the concrete guard
  against the past collision incident.
- **Consent-revocation cascade scope** — deciding *how far* a revoke cascades
  (just future authorizations, or also active sessions/refresh tokens for that
  RP). This plan cascades to the RP's tokens via the shipped revocation stack;
  confirm that's the desired UX.
- **`prompt` param completeness** — full OIDC `prompt` semantics (`none`,
  `login`, `consent`, `select_account`) interact with consent; this plan
  covers `consent`/`none` for the consent decision and defers the rest to the
  existing login flow.
- **Scope-set representation** — canonical ordering matters for the
  superset check; pick one representation (sorted space-delimited string vs
  array column) and enforce it at the store boundary.

## Definition of done

`go build/vet/test ./...` green; `consent_grants` (migration 0011) present with
sqlc queries; `/authorize` skips the prompt for a covering grant, re-prompts on
no-grant / scope-escalation / revoked grant, and honours `prompt=consent`; users
can list and revoke their consent grants via harbor-mgmt with an RP-token
cascade; consent events are emitted for the audit trail; no cross-user/
cross-client leakage; `make agent-check` clean. Ready to `@plan promote`.
