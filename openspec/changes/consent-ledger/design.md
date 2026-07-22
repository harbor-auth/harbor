# Design: Consent ledger (per-user / per-RP / per-scope consent grants)

## Key Decisions

### Decision 1: A dedicated `consent_grants` table keyed by `(user_id, client_id)`
**Chosen:** Store consent in its own table keyed by both `user_id` and
`client_id`, carrying the granted scope set and a nullable `revoked_at`.
**Rationale:** Consent is per-(user, RP): it must express "granted `email` but
not `profile`", survive re-login, and be independently revocable. A dedicated
table is the only shape that expresses and revokes that tuple cleanly.
**Alternatives considered:** Infer consent from the presence of a
session/refresh token (rejected — a session is authentication state, not a
durable, revocable authorisation record); store consent inside the client
registry row (rejected — consent is per-(user, client), not per-client).

### Decision 2: Canonical scope set → escalation is a superset check
**Chosen:** Persist scopes as a normalised (sorted, deduped) set; treat a
request as an **escalation** when requested ⊄ granted, and skip the prompt only
when granted ⊇ requested.
**Rationale:** Makes the skip-vs-prompt decision exact and deterministic, and
lets an approval widen the grant by set union. Canonicalisation at the store
boundary avoids ordering ambiguity.
**Alternatives considered:** Compare raw scope strings (rejected —
order-sensitive, brittle); store one row per (user, client, scope) (rejected —
more rows, no benefit over a canonical set column for the superset check).

### Decision 3: Skip-vs-prompt honours the OIDC `prompt` parameter
**Chosen:** A covering grant skips the consent ceremony, but `prompt=consent`
always forces re-consent and `prompt=none` errors when consent would be
required.
**Rationale:** Frictionless SSO is the goal, but the RP (and spec) must be able
to force an explicit consent or require silent auth. Honouring `prompt` keeps
the skip optimisation OIDC-compliant.
**Alternatives considered:** Always prompt (rejected — defeats frictionless SSO,
trains click-through consent); never re-prompt once granted (rejected — breaks
`prompt=consent` and scope-escalation safety).

### Decision 4: Revocation cascades an RP token/session revocation
**Chosen:** Revoking a consent grant sets `revoked_at` **and** cascades a
token/session revocation for that RP via the shipped revocation stack.
**Rationale:** "Withdraw consent" must actually take effect — leaving live
refresh tokens for an RP the user just de-authorised would be a privacy
footgun. Reusing the shipped revocation stack keeps one revocation mechanism.
**Alternatives considered:** Revoke future authorizations only, leaving active
tokens (rejected — the RP keeps access until token expiry, contradicting the
user's intent).

### Decision 5: Regional, minimal-PII authorisation metadata
**Chosen:** Consent state lives with the user's row in their home jurisdiction
(no cross-region lookup) and holds no PII beyond the `user_id`/`client_id` FKs
and scope strings.
**Rationale:** Consistent with §5 data sovereignty and the §2.1 promise that the
operator cannot mine consent for tracking. The envelope seam is available if
per-user encryption of the scope set is ever required.
**Alternatives considered:** A global consent table (rejected — cross-region
lookup, breaks sovereignty); encrypt the scope set now (deferred — the row is
authorisation metadata, not content; noted, not built).
