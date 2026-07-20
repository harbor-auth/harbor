-- 0010_revoked_jtis (up) — emergency JWT revocation via bloom filter (DESIGN §3.5).
--
-- This table is the persistent source of truth for revoked JTIs. The in-process
-- bloom filter (checked on every token verification) is rehydrated from this
-- table on startup and kept in sync via Redis pub/sub.
--
-- NOT a user-owned row (no region column): JTIs are opaque token identifiers,
-- not PII. The user_id is deliberately NOT stored here to avoid creating a
-- queryable token-to-user mapping.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

CREATE TABLE revoked_jtis (
    jti        text PRIMARY KEY,            -- JWT ID (UUID string, 36 bytes)
    revoked_at timestamptz NOT NULL DEFAULT now(),
    reason     text NOT NULL,               -- 'emergency_kill' | 'key_rotation' | 'user_request'
    expires_at timestamptz NOT NULL,        -- JWT's original exp; used for GC

    CONSTRAINT revoked_jtis_reason_valid CHECK (reason IN ('emergency_kill', 'key_rotation', 'user_request'))
);

-- Index for GC queries: DELETE FROM revoked_jtis WHERE expires_at < now()
-- Run nightly to prune entries for expired JWTs (no longer need revocation).
CREATE INDEX idx_revoked_jtis_expires_at ON revoked_jtis (expires_at);
