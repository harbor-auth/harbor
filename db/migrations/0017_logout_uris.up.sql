-- 0017_logout_uris (up) — add logout_uris column to relying_parties for
-- RP-Initiated Logout (OIDC RP-Initiated Logout 1.0). This column stores the
-- registered post_logout_redirect_uri values that a client may use when calling
-- /end_session. Like redirect_uris, these MUST be exact-matched (no wildcards).
-- See docs/DESIGN.md §3.6 (logout) and openspec/changes/end-session-logout/.

ALTER TABLE relying_parties ADD COLUMN logout_uris text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN relying_parties.logout_uris IS 'Registered post-logout redirect URIs for RP-Initiated Logout (exact match only).';
