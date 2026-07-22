# client-secret-auth — Verify client_secret at the /token endpoint

> **Priority:** P0 (Wave 6, production-readiness audit blocker 1.6)
> **Effort:** 4–8 h · **Root feature** (reads the existing `client_secret_hash`
> column from migration `0012_client_registration`)

## Problem

`PostToken` (`internal/oidcapi/token.go`) parses `client_id` from the form but
**never extracts or verifies `client_secret`**:

```go
req := oidc.TokenRequest{
    GrantType: ..., Code: ..., RedirectURI: ...,
    ClientID:  r.PostFormValue("client_id"),
    ...
    // NO client_secret field!
}
```

Registration (`internal/mgmtapi/register.go`) already mints confidential
clients with `token_endpoint_auth_method` `client_secret_basic` /
`client_secret_post` and stores `client_secret_hash` (SHA-256, via
`mgmtapi.HashSecret`) in `relying_parties` — but nothing reads it at token
time. Any caller can use any confidential `client_id` without knowing its
secret. `oidcapi/auth.go` even carries an explicit scaffold:
`validateClientCredentials` — "actual secret comparison is not yet wired".

## Design

### 1. Expose auth material on the domain client

- `internal/oidc/store.go` `Client`: add
  - `TokenEndpointAuthMethod string` (`"none"`, `"client_secret_basic"`,
    `"client_secret_post"`; empty ⇒ treat per stored default)
  - `SecretHash []byte` (SHA-256 of the plaintext secret; never the plaintext)
- `internal/clients/registry.go` `rowToClient`: map
  `row.TokenEndpointAuthMethod` (nil → `"client_secret_basic"` per RFC 7591
  §2, matching registration's default) and `row.ClientSecretHash`.
- `internal/oidc` in-memory registry: carry the new fields (tests seed them).

### 2. Extract the secret in `PostToken`

- Add `ClientSecret string` to `oidc.TokenRequest` (`internal/oidc/token.go`).
- In `internal/oidcapi/token.go`:
  - Support **client_secret_basic**: if `Authorization: Basic` is present, use
    the existing `parseBasicAuth` (`internal/oidcapi/auth.go`); RFC 6749 §2.3.1
    — Basic takes precedence, and a client MUST NOT use both mechanisms in one
    request (if both are present with conflicting client_ids → `invalid_request`).
    Note RFC 6749 App. B: Basic credentials are form-urlencoded before base64 —
    apply `url.QueryUnescape` to both parts.
  - Support **client_secret_post**: `r.PostFormValue("client_secret")`.
  - Populate `req.ClientID` / `req.ClientSecret` from whichever source applied.

### 3. Verify in the service layer (both grant paths)

Add a single helper in `internal/oidc` (e.g. `authenticateClient(ctx, req)`)
called at the **top** of both `Service.Token` and `Service.Refresh`, before any
code/session lookup (never burn a code or fire a theft signal for an
unauthenticated client):

- Look up the client; unknown → `invalid_client`, 401.
- If `TokenEndpointAuthMethod == "none"` (public client): require that **no**
  secret was presented is NOT enforced (per RFC a public client simply doesn't
  authenticate) — PKCE remains the binding. Proceed.
- Confidential client (`client_secret_basic` / `client_secret_post`):
  - Missing secret → `invalid_client`, 401.
  - Compare: `subtle.ConstantTimeCompare(sha256(presentedSecret), storedHash)`.
    The stored hash is SHA-256 of a 256-bit random secret
    (`mgmtapi.HashSecret`), so SHA-256 + constant-time compare is correct here
    — the secret is high-entropy machine-generated, not a human password, so
    bcrypt/Argon2 stretching is unnecessary; **do not** switch the storage
    format in this change (migration 0012's comment says Argon2id but the code
    uses SHA-256 — fix the comment, not the code).
  - Mismatch → `invalid_client`, 401. Same error for "unknown client" vs "bad
    secret" (no existence disclosure, DESIGN §11.7).
  - Enforce the registered method: a `client_secret_basic` client presenting
    only via POST body (or vice versa) → `invalid_client` (strict per RFC 7591
    metadata).
- 401 responses: when the client attempted Basic auth, set
  `WWW-Authenticate: Basic` per RFC 6749 §5.2 (update the long comment in
  `writeOAuthError` — the "public-client-only" rationale is now obsolete; add
  the header on the Basic-attempted path only).

### 4. Retire the scaffold

- Replace the TODO body of `validateClientCredentials`
  (`internal/oidcapi/auth.go`) with a real hash comparison (shared helper) —
  this also closes the same hole on `/introspect`, which currently accepts any
  existing client_id with any secret.
- Remove all "inert"/"not yet wired" comments.

## Security notes

- Never log `client_secret` or its hash; log only `client_id` + error code.
- The secret must not appear in the rate-limit key path or metrics labels.
- `MaxBytesReader` 64KB cap already covers the added form field.

## Tests

`internal/oidc` (pure/service): public client unaffected; confidential client
with correct secret via post → success; wrong/missing secret → `invalid_client`
401 and — critically — the auth code is **not consumed** (retry with the right
secret succeeds); refresh grant equally gated; method mismatch rejected.

`internal/oidcapi`: Basic-auth parsing (incl. urlencoded chars and colons in
secret), Basic vs post precedence/conflict, 401 carries `WWW-Authenticate:
Basic` only for Basic attempts, `Cache-Control: no-store` on all error paths.

`internal/clients`: `rowToClient` maps `ClientSecretHash` +
`TokenEndpointAuthMethod` (nil → default).

Integration/e2e: register a confidential client via `/register`, complete a
code flow, exchange at `/token` with and without the secret.

## No scaffold remains

`validateClientCredentials`'s TODO is gone; `token.go`'s "inert" comment block
is rewritten; discovery (`token_endpoint_auth_methods_supported`) is updated to
advertise `client_secret_basic`/`client_secret_post` alongside `none` (and its
test `discovery_test.go` updated). Update
`docs/plans/production-readiness.md` row 1.6 → Resolved in the same change.
