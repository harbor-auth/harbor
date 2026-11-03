SET lock_timeout = '3s';
SET statement_timeout = '30s';
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM cloud_client_versions)
    OR EXISTS (SELECT 1 FROM relying_parties WHERE cloud_generation > 0) THEN
  RAISE EXCEPTION 'cannot discard cloud client generation fences; use a forward fix';
 END IF;
END $$;
DROP FUNCTION apply_cloud_client_mutation(text,text,text,bigint,bytea,jsonb);
DROP TRIGGER relying_parties_cloud_generation_guard ON relying_parties;
DROP FUNCTION guard_cloud_client_generation();
DROP TABLE cloud_client_versions;
ALTER TABLE relying_parties DROP CONSTRAINT relying_parties_cloud_generation_hash_check;
ALTER TABLE relying_parties DROP COLUMN cloud_generation, DROP COLUMN cloud_request_hash;
