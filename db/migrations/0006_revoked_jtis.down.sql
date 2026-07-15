-- 0006_revoked_jtis (down) — drop the emergency JWT revocation table.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

DROP TABLE IF EXISTS revoked_jtis;
