-- 0019_cloud_namespaces (up) — Harbor Cloud management API contract: the
-- namespace provisioning-lifecycle record, its idempotency ledger, and
-- namespace-scoped session records
-- (openspec/changes/harbor-cloud-management-api-contract-2ee993ea).
--
-- Three greenfield tables, owned by internal/cloudapi and reachable only via
-- harbor-mgmt's private /admin/v1/* surface:
--
--   - cloud_namespaces: the provisioning-lifecycle record Harbor Cloud
--     creates/deletes per self-hosted namespace. `id` is caller-supplied (the
--     id Harbor Cloud mints), not a generated uuid, because the create
--     handler must detect "namespace already exists" by that exact id
--     (409 namespace_already_exists). Delete is soft (deleted_at) so the
--     idempotent-delete contract (204 on an absent OR already-deleted
--     namespace, always) never depends on whether the row still exists.
--     This is a provisioning-lifecycle record ONLY, not a routing/PII
--     boundary — harbor-core stays single-tenant per region (design.md
--     Non-Goals).
--   - cloud_operations: the idempotency ledger shared by namespace
--     create/delete and session minting. Primary key (idempotency_key,
--     operation) lets the same key be reused across different operation
--     types without collision. request_hash lets a replayed key with a
--     different body be rejected (409 idempotency_key_reused); response_body
--     lets a replayed key with the same body replay the original response
--     verbatim (the stored JSON envelope includes the status code).
--   - cloud_sessions: short-lived, namespace-scoped credentials Harbor Cloud
--     mints to perform bounded provisioning operations against one
--     namespace — unrelated to end-user OIDC/BFF sessions. Only token_hash
--     is ever persisted; the plaintext bearer is returned once at mint time
--     (mirrors mgmtapi/register.go's credential-minting pattern).
--
-- This is an additive CREATE on a greenfield set of tables; the
-- expand/contract pattern (.agents/db-migrate.md, DESIGN §1.8) applies to
-- FUTURE changes.
--
-- Fail fast so a stuck migration never stalls the hot path (/authorize, /token).
SET lock_timeout = '3s';
SET statement_timeout = '30s';

-- cloud_namespaces — one row per Harbor Cloud-provisioned namespace.
CREATE TABLE cloud_namespaces (
    id         text PRIMARY KEY,          -- caller-supplied namespace id (Harbor Cloud mints it)
    status     text NOT NULL,             -- provisioning-lifecycle status (handler-owned enum)
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz               -- NULL while live; set by the idempotent soft-delete
);

-- cloud_operations — idempotency ledger for namespace create/delete and
-- session minting. A row is written once per (idempotency_key, operation);
-- retries look it up before doing any write.
CREATE TABLE cloud_operations (
    idempotency_key text NOT NULL,
    operation       text NOT NULL,        -- e.g. "namespace.create", "namespace.delete", "session.mint"
    request_hash    bytea NOT NULL,       -- hash of the normalized request body
    response_body   jsonb NOT NULL,       -- verbatim response envelope (status + body) to replay
    created_at      timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (idempotency_key, operation)
);

-- cloud_sessions — namespace-scoped provisioning credentials minted for
-- Harbor Cloud. Not an OIDC/BFF session.
CREATE TABLE cloud_sessions (
    session_id   text PRIMARY KEY,
    namespace_id text NOT NULL REFERENCES cloud_namespaces (id),
    token_hash   bytea NOT NULL,          -- only the hash is persisted; plaintext returned once at mint
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz,             -- NULL until the session is used/invalidated
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Supports namespace-scoped session lookups (e.g. cross-tenant checks and
-- future per-namespace session listing).
CREATE INDEX idx_cloud_sessions_namespace_id ON cloud_sessions (namespace_id);
