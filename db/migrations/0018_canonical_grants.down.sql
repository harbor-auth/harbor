-- 0018_canonical_grants (down) — restore the legacy consent table.

SET lock_timeout = '3s';
SET statement_timeout = '30s';

DROP VIEW consent_grants;

CREATE TABLE consent_grants (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id   text NOT NULL REFERENCES relying_parties (client_id),
    scopes      text[] NOT NULL DEFAULT '{}',
    granted_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz
);

INSERT INTO consent_grants (
    id, user_id, client_id, scopes, granted_at, updated_at, revoked_at
)
SELECT id, user_id, client_id, scopes, created_at, created_at, revoked_at
FROM grants;

CREATE INDEX idx_consent_grants_user_id ON consent_grants (user_id);
CREATE UNIQUE INDEX idx_consent_grants_user_client_active
    ON consent_grants (user_id, client_id)
    WHERE revoked_at IS NULL;
