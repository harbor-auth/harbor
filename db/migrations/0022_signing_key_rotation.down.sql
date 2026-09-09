SET lock_timeout = '3s';
SET statement_timeout = '30s';

-- Do not silently discard a rotation in progress during a schema rollback.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM signing_keys WHERE state = 'draining'
        OR (state = 'retired' AND promoted_at IS NULL)) THEN
        RAISE EXCEPTION 'signing key lifecycle cannot be represented by the old schema';
    END IF;
END $$;
ALTER TABLE signing_keys
    DROP CONSTRAINT signing_keys_state_valid,
    DROP CONSTRAINT signing_keys_state_timestamps,
    DROP COLUMN promote_after,
    DROP COLUMN retire_after,
    ADD CONSTRAINT signing_keys_state_valid CHECK (state IN ('pending', 'active', 'retired')),
    ADD CONSTRAINT signing_keys_state_timestamps CHECK (
        (state = 'pending' AND promoted_at IS NULL AND retired_at IS NULL)
        OR (state = 'active' AND promoted_at IS NOT NULL AND retired_at IS NULL)
        OR (state = 'retired' AND promoted_at IS NOT NULL AND retired_at IS NOT NULL)
    );
