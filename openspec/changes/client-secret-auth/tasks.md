# client-secret-auth — Tasks

> Plan: `docs/plans/client-secret-auth.md` · Blocker 1.6 in
> `docs/plans/production-readiness.md`. Makes `/token` (and `/introspect`)
> actually verify `client_secret` against the stored hash.

## 1. Domain model — `internal/oidc`

- [ ] `store.go` `Client`: add `TokenEndpointAuthMethod string` and
      `SecretHash []byte`.
- [ ] `token.go` `TokenRequest`: add `ClientSecret string`.
- [ ] New `authenticateClient` helper: looks up the client and, for
      confidential clients (`client_secret_basic` / `client_secret_post`),
      verifies `subtle.ConstantTimeCompare(sha256(presented), SecretHash) == 1`;
      public clients (`none`) pass through (PKCE is their binding).
      Unknown client, missing secret, wrong secret, and auth-method mismatch
      all return the SAME `invalid_client` 401 (no existence disclosure).
- [ ] Call `authenticateClient` at the TOP of `Service.Token` AND
      `Service.Refresh` — before `Peek`/session lookup, so a bad secret never
      burns an auth code, never consumes a refresh token, and never fires a
      theft signal.

## 2. Registry mapping — `internal/clients/registry.go`

- [ ] `rowToClient`: map `row.ClientSecretHash` → `SecretHash` and
      `row.TokenEndpointAuthMethod` → `TokenEndpointAuthMethod`
      (nil → `"client_secret_basic"`, matching RFC 7591 §2 and the
      registration default in `internal/mgmtapi/register.go`).
- [ ] In-memory registry (`oidc.NewInMemoryClientRegistry`) carries the new
      fields; seed demo clients with `TokenEndpointAuthMethod: "none"`.

## 3. HTTP extraction — `internal/oidcapi/token.go`

- [ ] Extract `client_secret` from the POST form (`client_secret_post`).
- [ ] Support `client_secret_basic` via the existing `parseBasicAuth`
      (`internal/oidcapi/auth.go`); apply RFC 6749 App. B form-urlencoding
      (`url.QueryUnescape` on client_id and secret).
- [ ] Precedence/conflict: Basic wins; Basic + form credentials with
      mismatched client_id → `invalid_request` 400.
- [ ] On `invalid_client` 401 where Basic auth was attempted, set
      `WWW-Authenticate: Basic` (update the now-obsolete comment block in
      `writeOAuthError`).

## 4. Retire scaffolds

- [ ] `internal/oidcapi/auth.go` `validateClientCredentials`: replace the
      `_ = secret` TODO with the real constant-time hash comparison (shared
      with /token) — closes the same hole on `/introspect`.
- [ ] Remove every "inert" / "not yet wired" / SCAFFOLD comment on the client
      auth path.
- [ ] Fix the migration-0012 comment drift ("Argon2id") to state SHA-256 of a
      256-bit random secret (docs-only; do NOT change the hash format).

## 5. Discovery

- [ ] `token_endpoint_auth_methods_supported` in the discovery document:
      advertise `none`, `client_secret_basic`, `client_secret_post`; update
      `internal/oidcapi/discovery_test.go` accordingly.

## 6. Tests

- [ ] `internal/oidc`: public client (method `none`) flow unchanged;
      confidential client + correct secret → tokens; wrong/missing secret →
      `invalid_client` 401 AND the auth code is NOT consumed (retry with the
      correct secret succeeds); same gating on `Refresh`; registered-method
      mismatch (basic client using post, and vice versa) → `invalid_client`.
- [ ] `internal/oidcapi`: Basic parsing edge cases (colon in secret,
      urlencoded chars, malformed base64); precedence/conflict handling;
      `WWW-Authenticate: Basic` only when Basic was attempted;
      `Cache-Control: no-store` on all error responses.
- [ ] `internal/clients`: `rowToClient` maps hash + auth method, nil-method
      default.
- [ ] Integration/e2e: register a confidential client (RFC 7591), run the
      code flow, exchange at `/token` with the minted secret (success) and
      without/with a wrong secret (401).
- [ ] Assert no log line ever contains the secret or its hash.
- [ ] `go build ./... && go test ./...` green.

## 7. Docs / hygiene

- [ ] Strike blocker 1.6 in `docs/plans/production-readiness.md` in the same
      change; note the RFC 7009 revoke re-verification follow-up.
