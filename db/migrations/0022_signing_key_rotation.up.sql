SET lock_timeout = '3s';
SET statement_timeout = '30s';

-- Durable rotation schedules and a public-key overlap state.
ALTER TABLE signing_keys
    ADD COLUMN promote_after timestamptz,
    ADD COLUMN retire_after timestamptz,
    DROP CONSTRAINT signing_keys_state_valid,
    DROP CONSTRAINT signing_keys_state_timestamps,
    ADD CONSTRAINT signing_keys_state_valid CHECK (state IN ('pending', 'active', 'draining', 'retired')),
    ADD CONSTRAINT signing_keys_state_timestamps CHECK (
        (state = 'pending' AND promoted_at IS NULL AND retired_at IS NULL)
        OR (state IN ('active', 'draining') AND promoted_at IS NOT NULL AND retired_at IS NULL)
        OR (state = 'retired' AND retired_at IS NOT NULL)
    );
