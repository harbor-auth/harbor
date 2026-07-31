-- 0017_logout_uris (up) — add logout_uris column to relying_parties for
-- RP-Initiated Logout (OIDC RP-Initiated Logout 1.0). This column stores the
-- registered post_logout_redirect_uri values that a client may use when calling
-- /end_session. Like redirect_uris, these MUST be exact-matched (no wildcards).
-- See docs/DESIGN.md §3.6 (logout) and openspec/changes/end-session-logout/.
--
-- Note: migration 0014 was intentionally skipped; the sequence jumps from
-- 0013_audit_events to 0015_recovery_codes (0014 was reserved and never used).
--
-- Fail fast so a stuck migration never stalls the hot path (/authorize, /token).
SET lock_timeout = '3s';
SET statement_timeout = '30s';

ALTER TABLE relying_parties ADD COLUMN logout_uris text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN relying_parties.logout_uris IS 'Registered post-logout redirect URIs for RP-Initiated Logout (exact match only).';
