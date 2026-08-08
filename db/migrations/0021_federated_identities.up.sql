-- 0021_federated_identities (up) — the corporate-SSO handoff's identity
-- mapping table (docs/plans/sso-user-session-handoff.md).
--
-- Harbor Cloud's SAML bridge authenticates a corporate user against their
-- own IdP and hands the resulting (namespace, subject) pair to Harbor via
-- POST /admin/v1/user-sessions. Harbor has no email column and no user
-- lookup by anything but id (docs/DESIGN.md §10) — account-linking by email
-- is structurally impossible here, by design. federated_identities is the
-- ONLY mapping from an external identity to a Harbor user id, and it is
-- namespace-scoped: the same IdP subject in two different namespaces maps to
-- two distinct Harbor users (a corporate tenant never silently shares an
-- account with another tenant that happens to reuse a subject string).
--
-- subject_hmac, not subject: the raw IdP NameID is never stored — only its
-- HMAC-SHA256 (keyed by SSO_SUBJECT_HMAC_KEY, internal/cloudapi/usersessions.go)
-- is persisted, the same reasoning as BrowserNonceHash — a table dump yields
-- no re-identifiable subject material.
--
-- key_version exists from day one, even though nothing rotates it yet,
-- because rotation is the one thing that becomes IMPOSSIBLE to add later:
-- the raw NameID is never stored (only its HMAC), so a pepper rotation can
-- only re-key a row lazily, at the next login, by minting a NEW row under
-- the new key_version and leaving the old row in place until it ages out
-- (never a bulk UPDATE, which would require the plaintext subject Harbor
-- deliberately never has). Without this column reserved now, rotating the
-- pepper would require a backwards-incompatible migration; with it, rotation
-- is a day-two operational change to the verifier only.
--
-- No UNIQUE(user_id): a user is not guaranteed to have exactly one federated
-- identity row forever — a future lazy re-key (above) intentionally leaves
-- both the old and new key_version rows pointing at the same user_id for a
-- transition window.
--
-- Fail fast so a stuck migration never stalls the hot path (/authorize, /token).
SET lock_timeout = '3s';
SET statement_timeout = '30s';

-- federated_identities — maps a namespace-scoped, HMAC'd external subject to
-- the Harbor user it resolves to.
CREATE TABLE federated_identities (
    namespace_id text        NOT NULL REFERENCES cloud_namespaces (id),
    subject_hmac bytea       NOT NULL,       -- HMAC-SHA256(subject), never the raw subject
    key_version  smallint    NOT NULL DEFAULT 1, -- the SSO_SUBJECT_HMAC_KEY version used above
    user_id      uuid        NOT NULL REFERENCES users (id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (namespace_id, subject_hmac, key_version)
);

-- Supports "does this user have a federated identity" lookups (e.g. future
-- compliance export / erasure of federated mappings) without a table scan.
CREATE INDEX idx_federated_identities_user ON federated_identities (user_id);
