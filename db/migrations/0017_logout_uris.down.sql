-- 0017_logout_uris (down) — remove logout_uris column from relying_parties.

ALTER TABLE relying_parties DROP COLUMN IF EXISTS logout_uris;
