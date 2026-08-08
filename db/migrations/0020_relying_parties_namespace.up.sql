-- 0020_relying_parties_namespace (up) — let a relying_parties row be owned
-- by a Harbor Cloud namespace, and let it be soft-deleted
-- (feat/cloud-oidc-client-provisioning: namespace-scoped OIDC client CRUD on
-- /admin/v1/namespaces/{namespace}/clients).
--
-- Expand pattern (docs/DESIGN.md §1.8, .agents/db-migrate.md): purely additive
-- ALTERs, both columns NULLABLE, no backfill.
--
--   - namespace_id: the cloud_namespaces row that provisioned this client, or
--     NULL. NULL is a PERMANENT, legitimate terminal state — it means "not
--     owned by a cloud namespace" (an operator-registered or dynamically
--     RFC-7591-registered client), not "not yet backfilled". There is
--     intentionally no backfill: every relying_parties row that predates this
--     migration stays namespace_id IS NULL forever, and every namespaced
--     client CRUD route (internal/cloudapi/clients.go) must treat such a row
--     as invisible to the namespace it queries by.
--   - deleted_at: a namespaced client's DELETE route cannot hard-delete the
--     row. grants.client_id (0001_init.up.sql) and relay_addresses.client_id
--     (0016_relay_addresses.up.sql) both reference relying_parties(client_id)
--     with NO ON DELETE CASCADE, so a hard DELETE would raise SQLSTATE 23503
--     for any client a user has ever consented to or that has an active relay
--     address. Soft-delete sidesteps that: the row stays in place for the FKs,
--     and GetRelyingParty (db/queries/relying_parties.sql) now filters
--     deleted_at IS NULL so a soft-deleted client immediately stops
--     authenticating at /token, /authorize, /introspect, and /revoke.
--
-- Fail fast so a stuck migration never stalls the hot path (/authorize, /token).
SET lock_timeout = '3s';
SET statement_timeout = '30s';

ALTER TABLE relying_parties ADD COLUMN namespace_id text REFERENCES cloud_namespaces (id);
ALTER TABLE relying_parties ADD COLUMN deleted_at timestamptz;

-- Partial index: only namespaced rows are ever looked up by namespace_id (the
-- namespaced CRUD routes always scope by it), and most relying_parties rows
-- will have it NULL forever (see above) — indexing only the non-NULL subset
-- keeps the index small and keeps a NULL-namespace client out of it entirely.
CREATE INDEX idx_relying_parties_namespace_id ON relying_parties (namespace_id) WHERE namespace_id IS NOT NULL;
