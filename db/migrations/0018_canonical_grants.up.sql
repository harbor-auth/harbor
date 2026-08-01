-- 0018_canonical_grants (up) — make grants the sole consent authority.
--
-- A consent_grants row does not contain the region or pairwise subject needed
-- to create a safe grant. Therefore only its consent-specific fields are moved
-- onto the already-existing canonical grant. Orphans abort the migration: a
-- fabricated PPID would silently change the subject an RP sees.

SET lock_timeout = '3s';
SET statement_timeout = '30s';

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM consent_grants AS consent
        LEFT JOIN grants AS canonical
          ON canonical.user_id = consent.user_id
         AND canonical.client_id = consent.client_id
        WHERE consent.revoked_at IS NULL
          AND canonical.id IS NULL
    ) THEN
        RAISE EXCEPTION 'active consent_grants row has no canonical grant';
    END IF;
END
$$;

UPDATE grants AS canonical
SET scopes = consent.scopes,
    created_at = LEAST(canonical.created_at, consent.granted_at),
    revoked_at = NULL
FROM consent_grants AS consent
WHERE consent.user_id = canonical.user_id
  AND consent.client_id = canonical.client_id
  AND consent.revoked_at IS NULL;

DROP TABLE consent_grants;

-- Keep the old read/update shape available during a rolling deployment. This
-- simple view is automatically updatable by PostgreSQL, but stores no state of
-- its own: grants is the only authority.
CREATE VIEW consent_grants AS
SELECT id,
       user_id,
       client_id,
       scopes,
       created_at AS granted_at,
       created_at AS updated_at,
       revoked_at
FROM grants;
