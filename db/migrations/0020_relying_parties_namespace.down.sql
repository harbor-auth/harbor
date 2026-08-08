-- 0020_relying_parties_namespace (down) — remove the namespace-ownership and
-- soft-delete columns added in the up migration.
--
-- HAZARD (M5): dropping deleted_at discards every soft-delete tombstone.
-- Every namespaced OIDC client ever deleted through
-- DELETE /admin/v1/namespaces/{namespace}/clients/{client_id} (directly, or
-- via cascade from DELETE /admin/v1/namespaces/{namespace}) authenticates
-- again at /token, /authorize, /introspect, and /revoke as soon as this
-- migration is re-applied — the row was never removed (see the up
-- migration's deleted_at bullet), so dropping the column that GetRelyingParty
-- filters on is indistinguishable from undeleting every one of them at once.
-- There is no way to preserve tombstones through a column drop; do not run
-- this rollback on a deployment that has provisioned namespaced clients
-- without first confirming every currently-soft-deleted client_id is
-- acceptable to resurrect.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

DROP INDEX IF EXISTS idx_relying_parties_namespace_id;
ALTER TABLE relying_parties DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE relying_parties DROP COLUMN IF EXISTS namespace_id;
