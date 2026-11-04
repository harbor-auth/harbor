BEGIN;
SET lock_timeout = '3s';
SET statement_timeout = '30s';
LOCK TABLE grants, sessions IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM grants GROUP BY user_id,client_id HAVING count(*)>1) THEN
   RAISE EXCEPTION 'cannot restore unconditional uniqueness without deleting grant history';
 END IF;
END $$;
DROP INDEX idx_grants_user_client;
CREATE UNIQUE INDEX idx_grants_user_client ON grants(user_id,client_id);
ALTER TABLE sessions DROP COLUMN scopes, DROP COLUMN auth_time, DROP COLUMN acr, DROP COLUMN amr;
ALTER TABLE grants DROP COLUMN email_consent;
COMMIT;
