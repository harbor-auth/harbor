# consent-ledger

Persist per-user / per-RP / per-scope consent grants and enforce them at
`/authorize`. Adds a `consent_grants` table (migration 0011) keyed by
`(user_id, client_id)` carrying the granted scope set and a nullable
`revoked_at`; the authorization flow consults it to **skip** the consent prompt
for a covering grant, **re-prompt** on no-grant / scope-escalation / revoked
grant, and honour the OIDC `prompt=consent`/`prompt=none` parameters. Users can
list and revoke their own grants via `harbor-mgmt`, with revocation cascading a
token/session revocation for that RP through the shipped revocation stack. Every
grant / escalation / revoke emits a structured consent event
(`consent.granted`, `consent.scope_escalated`, `consent.revoked`) for the user
audit trail. Consent state is regional (no cross-region lookup) and holds no PII
beyond the `user_id`/`client_id` FKs and scope strings.
