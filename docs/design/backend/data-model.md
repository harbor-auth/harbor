> **DESIGN §10** · [↑ DESIGN index](../../DESIGN.md) · prev: [stack](stack.md)

# Data Model

> Every user-owned table carries a `region` column; sensitive columns are **envelope-encrypted** (🔒). All lives in the user's home region only.

```sql
-- Region is encoded in ids and issuer; PII never crosses regions.

users (
  id            uuid pk,          -- opaque, region-prefixed externally
  region        text,             -- 'eu' | 'us' | ...  (home jurisdiction)
  status        text,             -- active | locked | erased
  dek_wrapped   bytea 🔒,         -- per-user DEK, wrapped by regional KEK
  pairwise_secret bytea 🔒,       -- for PPID derivation
  created_at    timestamptz
)

credentials (                      -- passkeys (primary) + optional password
  id            uuid pk,
  user_id       uuid fk,
  type          text,             -- 'passkey' | 'password'
  webauthn_pubkey bytea,          -- COSE public key
  webauthn_aaguid bytea,
  sign_count    bigint,
  password_hash bytea 🔒,         -- Argon2id, only if type='password'
  created_at    timestamptz
)

mfa_factors (
  id            uuid pk,
  user_id       uuid fk,
  type          text,             -- 'totp' | 'recovery_code' | 'hardware_key'
  secret        bytea 🔒,         -- encrypted TOTP secret
  code_hash     bytea,            -- hashed recovery code
  used          bool
)

relying_parties (                  -- RP/client registry (NO user data)
  client_id     text pk,
  name          text,
  sector_id     text,             -- groups redirect URIs for PPID
  redirect_uris text[],
  token_format  text,             -- 'jwt' | 'opaque'
  scopes_allowed text[]
)

grants (                           -- user↔RP consent
  id            uuid pk,
  user_id       uuid fk,
  client_id     text fk,
  pairwise_sub  text,             -- PPID this RP sees for this user
  scopes        text[],           -- consented claims only
  created_at    timestamptz,
  revoked_at    timestamptz
)

sessions (
  id            uuid pk,
  user_id       uuid fk,
  device_label  text,
  refresh_token_hash bytea,       -- opaque, rotating, one-time-use
  expires_at    timestamptz,
  revoked_at    timestamptz
)

audit_events (                     -- user-visible auth trail
  id            uuid pk,
  user_id       uuid fk,
  event_type    text,             -- login_success | login_fail | grant_added | ...
  client_id     text,
  occurred_at   timestamptz
  -- deliberately: NO cross-RP profiling, NO RP-internal activity
)
```

**PPID derivation** (§3.2): `pairwise_sub = B64URL(HMAC-SHA256(pairwise_secret, sector_id || user_id))`.
