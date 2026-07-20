-- 0008_signing_keys (down) — drop the signing_keys table (indexes drop automatically).
SET lock_timeout = '3s';
SET statement_timeout = '30s';

DROP TABLE IF EXISTS signing_keys;
