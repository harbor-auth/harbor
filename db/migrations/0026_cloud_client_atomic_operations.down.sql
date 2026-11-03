SET lock_timeout = '3s';
SET statement_timeout = '30s';
-- Removing atomicity while accepted client operations exist would reintroduce
-- conflicting writes on old keys. Retain the contract and use a forward fix.
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM cloud_operations WHERE operation IN ('client.create','client.update','client.delete')) THEN
   RAISE EXCEPTION 'cannot discard atomic client operation protection; use a forward fix';
 END IF;
END $$;
DROP FUNCTION apply_cloud_client_operation(text,text,text,bigint,bytea,jsonb,text,text,bytea);
