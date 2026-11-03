-- Client configuration writes and their durable idempotency identity commit
-- together. The generation function remains the authority even on retries.
SET lock_timeout = '3s';
SET statement_timeout = '30s';
CREATE FUNCTION apply_cloud_client_operation(
 p_action text, p_namespace text, p_client text, p_generation bigint,
 p_request_hash bytea, p_config jsonb, p_key text, p_operation text, p_operation_hash bytea
) RETURNS jsonb LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
 prior_hash bytea;
 result jsonb;
 expected_operation text;
BEGIN
 expected_operation := CASE p_action WHEN 'create' THEN 'client.create'
   WHEN 'delete' THEN 'client.delete' ELSE 'client.update' END;
 IF p_key IS NULL OR length(p_key) = 0 OR p_operation IS DISTINCT FROM expected_operation
    OR p_operation_hash IS NULL OR octet_length(p_operation_hash) <> 32 THEN
   RAISE EXCEPTION 'invalid client operation identity' USING ERRCODE = '22023';
 END IF;
 -- Never occupy a connection waiting for a competing operation transaction.
 -- A hash collision only causes a conservative retry; the durable key is exact.
 IF NOT pg_try_advisory_xact_lock(hashtextextended(jsonb_build_array(p_key,p_operation)::text, 294352)) THEN
   RETURN jsonb_build_object('outcome','operation_in_progress');
 END IF;
 SELECT request_hash INTO prior_hash FROM cloud_operations
   WHERE idempotency_key=p_key AND operation=p_operation;
 IF FOUND AND prior_hash IS DISTINCT FROM p_operation_hash THEN
   RETURN jsonb_build_object('outcome','idempotency_conflict');
 END IF;
 result := apply_cloud_client_mutation(p_action,p_namespace,p_client,p_generation,p_request_hash,p_config);
 IF result->>'outcome' IN ('applied','replayed') AND prior_hash IS NULL THEN
   -- No credential material is recorded. Client handlers regenerate the HTTP
   -- response from the fenced result, never from this acceptance receipt.
   INSERT INTO cloud_operations(idempotency_key,operation,request_hash,response_body)
   VALUES(p_key,p_operation,p_operation_hash,jsonb_build_object(
     'status',CASE p_action WHEN 'delete' THEN 204 WHEN 'create' THEN 201 ELSE 200 END,
     'body',jsonb_build_object('client_id',p_client,'namespace_id',p_namespace,'generation',p_generation)));
 END IF;
 RETURN result;
END $$;
