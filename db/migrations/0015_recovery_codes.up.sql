-- 0015_recovery_codes (up) — recovery codes and lockout tracking for account
-- recovery (DESIGN §10, fail-closed recovery).
--
-- recovery_codes: stores hashed recovery codes per user. Each code is single-use
-- (used_at is set when consumed). Codes are hashed with a per-code salt for
-- defense-in-depth.
--
-- recovery_attempts: tracks failed recovery attempts per user for rate-limiting
-- and lockout. Fail-closed: too many failures lock the user out until
-- locked_until expires.
--
-- Greenfield schema; follows expand pattern (.agents/db-migrate.md, DESIGN §1.8).
--
-- Fail fast so a stuck migration never stalls the hot path (/authorize, /token).
SET lock_timeout = '3s';
SET statement_timeout = '30s';

-- recovery_codes — hashed single-use recovery codes per user.
CREATE TABLE recovery_codes (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash   bytea NOT NULL,             -- 🔒 hashed recovery code (never plaintext)
    salt        bytea NOT NULL,             -- per-code salt for hash
    used_at     timestamptz,                -- NULL while unused; set when consumed
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Index for user-centric queries (list/validate codes for a user).
CREATE INDEX idx_recovery_codes_user_id ON recovery_codes (user_id);

-- Unique constraint: a user cannot have duplicate code hashes.
CREATE UNIQUE INDEX idx_recovery_codes_user_code_hash
    ON recovery_codes (user_id, code_hash);

-- recovery_attempts — per-user lockout tracking for fail-closed recovery.
CREATE TABLE recovery_attempts (
    user_id       uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    failed_count  integer NOT NULL DEFAULT 0,
    locked_until  timestamptz                -- NULL when not locked; set after too many failures
);
