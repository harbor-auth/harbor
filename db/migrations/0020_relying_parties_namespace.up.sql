-- 0020_relying_parties_namespace (up) — let a relying_parties row be owned
-- by a Harbor Cloud namespace, and let it be soft-deleted
-- (feat/cloud-oidc-client-provisioning: namespace-scoped OIDC client CRUD on
-- /admin/v1/namespaces/{namespace}/clients).
--
-- HAZARD (M5, read before ever rolling this migration back): the down
-- migration DROPs both columns added here, discarding every deleted_at
-- tombstone along with them. If this migration is ever rolled back after
-- namespaced clients have been soft-deleted through the API, EVERY client
-- deleted via DELETE /admin/v1/namespaces/{namespace}/clients/{client_id} (or
-- cascade-deleted via DELETE /admin/v1/namespaces/{namespace}) resumes
-- authenticating at /token the moment this migration is re-applied — a
-- soft-deleted client's row still exists (see the deleted_at bullet below),
-- and dropping the column that hid it makes it live again with no code
-- change required. There is no way to preserve tombstones through a column
-- drop; the honest fix is this warning, not a workaround. Do not roll this
-- migration back on any deployment that has provisioned namespaced clients
-- without first confirming every currently-soft-deleted client_id is
-- acceptable to resurrect.
--
-- M2: also note client_id reuse is permanently burned by soft-delete — see
-- the deleted_at bullet below.
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
--     M2: because client_id remains the table's PRIMARY KEY and the row is
--     never removed, a soft-deleted client_id is burned PERMANENTLY —
--     CreateNamespacedClient's ON CONFLICT-free INSERT (relying_parties.sql)
--     hits the same primary-key violation for a deleted row as for a live
--     one, so delete-then-recreate-under-the-same-client_id is impossible.
--     A caller that needs the same logical client again must mint a new
--     client_id (api/openapi/harbor-cloud.yaml documents this on
--     ClientCreateRequest.client_id and the DELETE operation).
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
