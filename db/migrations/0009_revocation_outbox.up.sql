-- 0009_revocation_outbox (up) — durable outbox for theft-signal revocation
-- (DESIGN §3.5, §3.5.2, §10).
--
-- Both signalRefreshReuse() and signalCodeReuse() in internal/oidc/service.go
-- currently use in-process best-effort revocation. Transient failures silently
-- drop revocation signals, leaving stolen tokens active. This table implements
-- the transactional outbox pattern: revocation signals are written here first,
-- then a background worker polls and delivers them with retry.
--
-- Greenfield schema (no live rows today), but we follow the expand pattern
-- (.agents/db-migrate.md, DESIGN §1.8) for forward-compat with real deploys.
--
-- Fail fast so a stuck migration never stalls the hot path (/authorize, /token).
SET lock_timeout = '3s';
SET statement_timeout = '30s';

CREATE TABLE revocation_outbox (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    reason          text NOT NULL,              -- 'refresh_reuse' | 'code_reuse'
    user_id         uuid NOT NULL,              -- user whose sessions to revoke
    client_id       text NOT NULL,              -- RP scope for revocation
    grant_id        uuid REFERENCES grants (id) ON DELETE SET NULL,  -- nullable FK for audit provenance
    status          text NOT NULL DEFAULT 'pending',  -- 'pending' | 'delivered' | 'failed'
    retry_count     int NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),

    -- status must be one of the known values
    CONSTRAINT revocation_outbox_status_valid CHECK (status IN ('pending', 'delivered', 'failed')),
    -- reason must be one of the known signal types
    CONSTRAINT revocation_outbox_reason_valid CHECK (reason IN ('refresh_reuse', 'code_reuse'))
);

-- Partial index for worker polling: only pending rows, ordered by next_attempt_at.
-- This keeps the index small (delivered/failed rows are excluded) and efficient
-- for the SELECT ... WHERE status='pending' ORDER BY next_attempt_at query.
CREATE INDEX idx_revocation_outbox_pending
    ON revocation_outbox (next_attempt_at)
    WHERE status = 'pending';
