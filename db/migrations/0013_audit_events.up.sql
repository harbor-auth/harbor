-- 0013_audit_events (up) — add payload_encrypted column to audit_events for
-- envelope-encrypted event detail (user-audit-trail feature; DESIGN §2.1, §4.4,
-- §10, §11.6).
--
-- Expand pattern (DESIGN §1.8, .agents/db-migrate.md): additive ALTER with a
-- NULLABLE column so existing rows and currently-running code continue to work
-- unchanged. The column is bytea (raw ciphertext) — each event's detail is
-- envelope-encrypted under the user's DEK via the shipped Encryptor, so the
-- operator browsing the table sees only event_type + timestamp, never the
-- sensitive payload.
--
-- Crypto-shred (§11.6): because the payload is encrypted under users.dek_wrapped,
-- destroying that wrapped DEK renders all audit payloads permanently
-- unrecoverable, even from immutable backups. No row deletion required.
--
-- Fail fast so a stuck migration never stalls the hot path (/authorize, /token).
SET lock_timeout = '3s';
SET statement_timeout = '30s';

-- payload_encrypted: envelope-encrypted event detail (JSON ciphertext under the
-- user's DEK). NULL for legacy rows predating this migration. New rows emitted
-- by AuditRecorder will always populate this field.
ALTER TABLE audit_events ADD COLUMN payload_encrypted bytea;

COMMENT ON COLUMN audit_events.payload_encrypted IS 'Envelope-encrypted event detail (ciphertext under the user DEK). NULL for pre-migration rows. Operator sees only event_type + timestamp; crypto-shred via users.dek_wrapped destruction (DESIGN §4.4, §11.6).';
