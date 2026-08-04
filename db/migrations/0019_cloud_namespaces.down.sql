-- 0019_cloud_namespaces (down) — drop the Harbor Cloud management API
-- tables (cloud_sessions, cloud_operations, cloud_namespaces).
SET lock_timeout = '3s';
SET statement_timeout = '30s';

DROP INDEX IF EXISTS idx_cloud_sessions_namespace_id;
DROP TABLE IF EXISTS cloud_sessions;
DROP TABLE IF EXISTS cloud_operations;
DROP TABLE IF EXISTS cloud_namespaces;
