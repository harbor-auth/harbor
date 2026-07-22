-- 0001_init (down) — reverse the baseline in reverse dependency order.
SET lock_timeout = '3s';
SET statement_timeout = '30s';

DROP TABLE IF EXISTS grants;
DROP TABLE IF EXISTS relying_parties;
DROP TABLE IF EXISTS users;
