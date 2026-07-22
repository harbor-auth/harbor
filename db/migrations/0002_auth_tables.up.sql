-- 0002_auth_tables (up) — credentials, MFA factors, sessions, and the audit
-- trail (deferred from the 0001 baseline; DESIGN §10).
--
-- Every table here is a USER-OWNED row, so each carries `region` (DESIGN §10,
-- §5.4 — PII never leaves its home jurisdiction). Secrets/PII are stored as
-- envelope-encrypted `bytea` (wrapped by the per-user DEK; DESIGN §4.4, §7.3) or
-- as one-way hashes — never plaintext.
--
-- These are additive CREATEs on a greenfield schema; the expand/contract pattern
-- (.agents/db-migrate.md, DESIGN §1.8) applies to FUTURE changes on live tables.
--
-- Fail fast so a stuck migration never stalls the hot path (/authorize, /token).
SET lock_timeout = '3s';
SET statement_timeout = '30s';

-- credentials — passkeys (primary) + optional password (DESIGN §10, §3.1).
CREATE TABLE credentials (
    id              uuid PRIMARY KEY,
    region          text NOT NULL,          -- user-owned row: carries region (DESIGN §10)
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    type            text NOT NULL,          -- 'passkey' | 'password'
    webauthn_pubkey bytea,                  -- COSE public key (passkey)
    webauthn_aaguid bytea,                  -- authenticator model id
    sign_count      bigint NOT NULL DEFAULT 0,
    password_hash   bytea,                  -- 🔒 Argon2id, only when type='password'
    created_at      timestamptz NOT NULL DEFAULT now(),

    -- type↔field consistency (DESIGN §10): a credential is exactly one kind, and
    -- the field its kind requires must be present. Stops a half-populated row
    -- (e.g. a 'passkey' with no public key) from ever being stored.
    CONSTRAINT credentials_type_valid CHECK (type IN ('passkey', 'password')),
    CONSTRAINT credentials_type_fields CHECK (
        (type = 'passkey' AND webauthn_pubkey IS NOT NULL)
        OR (type = 'password' AND password_hash IS NOT NULL)
    )
);

CREATE INDEX idx_credentials_user_id ON credentials (user_id);

-- mfa_factors — encrypted TOTP secrets + hashed recovery codes (DESIGN §10).
CREATE TABLE mfa_factors (
    id         uuid PRIMARY KEY,
    region     text NOT NULL,               -- user-owned row: carries region (DESIGN §10)
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    type       text NOT NULL,               -- 'totp' | 'recovery_code' | 'hardware_key'
    secret     bytea,                       -- 🔒 envelope-encrypted TOTP secret
    code_hash  bytea,                       -- hashed recovery code (never plaintext)
    used       boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),

    -- type↔field consistency (DESIGN §10): each factor kind must carry its
    -- required secret material (a 'totp' needs its encrypted secret; a
    -- 'recovery_code' needs its hash). 'hardware_key' carries neither here.
    CONSTRAINT mfa_factors_type_valid CHECK (type IN ('totp', 'recovery_code', 'hardware_key')),
    CONSTRAINT mfa_factors_type_fields CHECK (
        (type = 'totp' AND secret IS NOT NULL)
        OR (type = 'recovery_code' AND code_hash IS NOT NULL)
        OR (type = 'hardware_key')
    )
);

CREATE INDEX idx_mfa_factors_user_id ON mfa_factors (user_id);

-- sessions — opaque, rotating, one-time-use refresh tokens; DB-backed so they
-- can be revoked (DESIGN §3.5, §10). Not on the hot path.
CREATE TABLE sessions (
    id                 uuid PRIMARY KEY,
    region             text NOT NULL,       -- user-owned row: carries region (DESIGN §10)
    user_id            uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_label       text,
    refresh_token_hash bytea NOT NULL,      -- opaque, one-time-use, hashed (never plaintext)
    created_at         timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    revoked_at         timestamptz
);

CREATE INDEX idx_sessions_user_id ON sessions (user_id);

-- audit_events — the user-visible auth trail (DESIGN §10, §11.6). Deliberately
-- holds NO cross-RP behavioral profile and NO RP-internal activity.
CREATE TABLE audit_events (
    id          uuid PRIMARY KEY,
    region      text NOT NULL,              -- user-owned row: carries region (DESIGN §10)
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    event_type  text NOT NULL,              -- login_success | login_fail | grant_added | ...
    client_id   text,                       -- optional RP context (which app), nothing more
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_events_user_id ON audit_events (user_id);
CREATE INDEX idx_audit_events_user_time ON audit_events (user_id, occurred_at DESC);
