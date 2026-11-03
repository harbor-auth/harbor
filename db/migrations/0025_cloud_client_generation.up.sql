-- Monotonic Cloud desired-state fencing. Generation zero is reserved for
-- registrations not yet managed through the versioned Cloud mutation API.
SET lock_timeout = '3s';
SET statement_timeout = '30s';
ALTER TABLE relying_parties
 ADD COLUMN cloud_generation bigint NOT NULL DEFAULT 0 CHECK (cloud_generation >= 0),
 ADD COLUMN cloud_request_hash bytea;
ALTER TABLE relying_parties ADD CONSTRAINT relying_parties_cloud_generation_hash_check
 CHECK ((cloud_generation = 0 AND cloud_request_hash IS NULL)
     OR (cloud_generation > 0 AND cloud_request_hash IS NOT NULL AND octet_length(cloud_request_hash) = 32));

-- No namespace FK: DELETE-before-create must persist a fence even when the
-- namespace does not exist yet. A foreign namespace can never fence its owner.
CREATE TABLE cloud_client_versions (
 namespace_id text NOT NULL,
 client_id text NOT NULL,
 generation bigint NOT NULL CHECK (generation > 0),
 request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
 deleted boolean NOT NULL,
 PRIMARY KEY (namespace_id, client_id)
);

-- Generic registration/bootstrap SQL must not overwrite or remove a versioned
-- row. INSERT locks before its uniqueness check, in the same order as the
-- versioned mutation function, so a delayed unversioned INSERT cannot race a
-- committed DELETE-before-create fence. UPDATE/DELETE already hold the RP row
-- lock and deliberately never acquire the advisory lock (no lock-order cycle).
CREATE FUNCTION guard_cloud_client_generation() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE f cloud_client_versions%ROWTYPE;
BEGIN
 IF TG_OP = 'DELETE' THEN
  IF OLD.cloud_generation > 0 THEN
   RAISE EXCEPTION 'versioned cloud client cannot be physically deleted' USING ERRCODE = '23514';
  END IF;
  RETURN OLD;
 END IF;
 IF TG_OP = 'INSERT' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.client_id, 294351));
 END IF;
 IF TG_OP = 'UPDATE' AND OLD.cloud_generation > 0 THEN
  -- A namespace's terminal deletion is a stronger operation than per-client
  -- mutation. Permit only its deletion bit; never metadata or credential drift.
  IF NEW.deleted_at IS NOT NULL AND NEW.namespace_id = OLD.namespace_id
     AND EXISTS (SELECT 1 FROM cloud_namespaces WHERE id = OLD.namespace_id AND deleted_at IS NOT NULL)
     AND (to_jsonb(NEW) - 'deleted_at') = (to_jsonb(OLD) - 'deleted_at') THEN
   RETURN NEW;
  END IF;
  IF NEW.cloud_generation <= OLD.cloud_generation AND NEW IS DISTINCT FROM OLD THEN
   RAISE EXCEPTION 'versioned cloud client requires a newer generation' USING ERRCODE = '23514';
  END IF;
 END IF;
 IF NEW.cloud_generation = 0 THEN
  IF EXISTS (SELECT 1 FROM cloud_client_versions WHERE client_id = NEW.client_id AND namespace_id = NEW.namespace_id) THEN
   RAISE EXCEPTION 'unversioned mutation of fenced cloud client' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO f FROM cloud_client_versions
 WHERE namespace_id = NEW.namespace_id AND client_id = NEW.client_id;
 IF NOT FOUND OR f.generation <> NEW.cloud_generation
    OR f.request_hash IS DISTINCT FROM NEW.cloud_request_hash
    OR (f.deleted AND NEW.deleted_at IS NULL) THEN
  RAISE EXCEPTION 'cloud client generation fence mismatch' USING ERRCODE = '23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER relying_parties_cloud_generation_guard
 BEFORE INSERT OR UPDATE OR DELETE ON relying_parties
 FOR EACH ROW EXECUTE FUNCTION guard_cloud_client_generation();

-- SECURITY INVOKER; search_path is captured from the migration, not the caller.
-- Every state decision and mutation occurs under one transaction-scoped global
-- client-ID lock. Fence and RP writes commit together, or neither commits.
CREATE FUNCTION apply_cloud_client_mutation(
 p_action text, p_namespace text, p_client text, p_generation bigint,
 p_request_hash bytea, p_config jsonb
) RETURNS jsonb LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
 f cloud_client_versions%ROWTYPE;
 rp relying_parties%ROWTYPE;
 has_rp boolean;
 ns_live boolean := false;
BEGIN
 IF p_action NOT IN ('create','update','upsert','delete') OR p_generation <= 0
    OR octet_length(p_request_hash) <> 32 THEN
  RAISE EXCEPTION 'invalid cloud mutation fence' USING ERRCODE = '22023';
 END IF;
 -- Lock namespace before client: terminal namespace deletion cannot race a
 -- new live client into existence. Missing namespaces are allowed for tombstones.
 SELECT deleted_at IS NULL INTO ns_live FROM cloud_namespaces
 WHERE id = p_namespace FOR SHARE;
 IF p_action <> 'delete' AND NOT coalesce(ns_live,false) THEN
  RETURN jsonb_build_object('outcome','namespace_inactive');
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_client, 294351));
 SELECT * INTO rp FROM relying_parties WHERE client_id = p_client FOR UPDATE;
 has_rp := FOUND;
 IF has_rp AND rp.namespace_id IS DISTINCT FROM p_namespace THEN
  IF p_action = 'delete' THEN
   has_rp := false; rp := NULL; -- Fence only the requesting namespace.
  ELSE
   RETURN jsonb_build_object('outcome',CASE WHEN p_action = 'create' THEN 'exists' ELSE 'missing' END);
  END IF;
 END IF;
 SELECT * INTO f FROM cloud_client_versions
 WHERE namespace_id = p_namespace AND client_id = p_client FOR UPDATE;
 IF FOUND THEN
  IF p_generation < f.generation THEN RETURN jsonb_build_object('outcome','stale'); END IF;
  IF p_generation = f.generation THEN
   IF p_request_hash IS DISTINCT FROM f.request_hash
      OR (f.deleted AND p_action <> 'delete') THEN
    RETURN jsonb_build_object('outcome','conflict');
   END IF;
   RETURN jsonb_build_object('outcome','replayed','client',
    CASE WHEN has_rp THEN to_jsonb(rp) || jsonb_build_object(
      'client_secret_hash',encode(rp.client_secret_hash,'base64'),
      'cloud_request_hash',encode(rp.cloud_request_hash,'base64')) ELSE NULL END);
  END IF;
  IF f.deleted AND p_action <> 'delete' THEN RETURN jsonb_build_object('outcome','conflict'); END IF;
 END IF;
 IF p_action = 'update' AND p_config ? '_expected_generation'
    AND rp.cloud_generation IS DISTINCT FROM (p_config->>'_expected_generation')::bigint THEN
  RETURN jsonb_build_object('outcome','stale');
 END IF;
 IF has_rp AND rp.deleted_at IS NOT NULL AND p_action <> 'delete' THEN
  RETURN jsonb_build_object('outcome','conflict');
 END IF;
 IF p_action = 'create' AND has_rp THEN RETURN jsonb_build_object('outcome','exists'); END IF;
 IF p_action = 'update' AND NOT has_rp THEN RETURN jsonb_build_object('outcome','missing'); END IF;

 INSERT INTO cloud_client_versions(namespace_id,client_id,generation,request_hash,deleted)
 VALUES(p_namespace,p_client,p_generation,p_request_hash,p_action='delete')
 ON CONFLICT(namespace_id,client_id) DO UPDATE SET
  generation=EXCLUDED.generation,request_hash=EXCLUDED.request_hash,deleted=EXCLUDED.deleted;
 IF p_action = 'delete' THEN
  IF has_rp THEN
   UPDATE relying_parties SET cloud_generation=p_generation,cloud_request_hash=p_request_hash,
     deleted_at=coalesce(deleted_at,now()) WHERE client_id=p_client AND namespace_id=p_namespace
   RETURNING * INTO rp;
  END IF;
 ELSE
  IF p_action = 'create' OR (p_action = 'upsert' AND NOT has_rp) THEN
   INSERT INTO relying_parties(client_id,namespace_id,name,sector_id,redirect_uris,token_format,
    scopes_allowed,client_secret_hash,grant_types,response_types,token_endpoint_auth_method,
    created_at,cloud_generation,cloud_request_hash)
   VALUES(p_client,p_namespace,p_config->>'name',p_client,
    ARRAY(SELECT jsonb_array_elements_text(p_config->'redirect_uris')),'jwt',
    ARRAY(SELECT jsonb_array_elements_text(p_config->'scopes_allowed')),
    decode(nullif(p_config->>'client_secret_hash',''),'hex'),
    ARRAY(SELECT jsonb_array_elements_text(p_config->'grant_types')),
    ARRAY(SELECT jsonb_array_elements_text(p_config->'response_types')),
    p_config->>'token_endpoint_auth_method',now(),p_generation,p_request_hash)
   RETURNING * INTO rp;
  ELSE
   UPDATE relying_parties SET name=p_config->>'name',
    redirect_uris=ARRAY(SELECT jsonb_array_elements_text(p_config->'redirect_uris')),
    scopes_allowed=ARRAY(SELECT jsonb_array_elements_text(p_config->'scopes_allowed')),
    client_secret_hash=decode(nullif(p_config->>'client_secret_hash',''),'hex'),
    grant_types=ARRAY(SELECT jsonb_array_elements_text(p_config->'grant_types')),
    response_types=ARRAY(SELECT jsonb_array_elements_text(p_config->'response_types')),
    token_endpoint_auth_method=p_config->>'token_endpoint_auth_method',
    cloud_generation=p_generation,cloud_request_hash=p_request_hash
   WHERE client_id=p_client AND namespace_id=p_namespace RETURNING * INTO rp;
  END IF;
 END IF;
 RETURN jsonb_build_object('outcome','applied','client',
  CASE WHEN rp.client_id IS NOT NULL THEN to_jsonb(rp) || jsonb_build_object(
   'client_secret_hash',encode(rp.client_secret_hash,'base64'),
   'cloud_request_hash',encode(rp.cloud_request_hash,'base64')) ELSE NULL END);
END;
$$;
