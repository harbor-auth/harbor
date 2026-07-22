-- 0016_relay_addresses (down) — drop the relay addresses table and indexes.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

DROP INDEX IF EXISTS idx_relay_addresses_user_id;
DROP INDEX IF EXISTS idx_relay_addresses_user_client;
DROP INDEX IF EXISTS idx_relay_addresses_relay_token;
DROP TABLE IF EXISTS relay_addresses;
