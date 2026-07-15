-- 0006_recovery_required (up) — add recovery_required column to users table.
--
-- Per REQ-005 (user-enrollment feature): new users must complete account
-- recovery setup before normal use. The column defaults to TRUE so that
-- existing users (if any) and new users start in the "must complete recovery"
-- state. The application sets it to FALSE via SetRecoveryComplete after the
-- user completes recovery credential enrollment.
--
-- Expand pattern (docs/DESIGN.md §1.8, .agents/db-migrate.md):
--   Phase 1 (this file): additive ALTER with NOT NULL DEFAULT true.
--   Greenfield schema (no live rows today) so the ALTER is instant.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

ALTER TABLE users ADD COLUMN recovery_required boolean NOT NULL DEFAULT true;
