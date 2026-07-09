-- 0002_auth_tables (down) — drop the §10 auth tables in reverse dependency order.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS mfa_factors;
DROP TABLE IF EXISTS credentials;
