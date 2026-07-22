# Proposal: Token introspection (RFC 7662 — POST /introspect)

## Problem

Harbor has no way for a relying party (or Harbor itself) to ask "is this token
still good?" The `bloom-filter-revocation` design explicitly names token
introspection as the false-positive confirmation path: a bloom filter hit means
*possibly revoked*, and without an introspection endpoint that hit either
wrongly blocks a valid token or is silently ignored, weakening the revocation
guarantee. Additionally, RPs that cannot (or do not want to) verify JWTs
locally have no standards-compliant validation path, and future opaque access
tokens (§3.3 opt-in) will *require* one. The endpoint is also privacy-sensitive
— it reveals token validity, `sub`, `scope`, and expiry — so it must be gated
behind authenticated, per-client access with strict cross-client isolation.

## Proposed Solution

Implement RFC 7662 `POST /introspect` on **harbor-hot** (not mgmt — this is a
latency-sensitive per-request surface with hot-path SLA guarantees).

**Contract:**

```
POST /introspect
Authorization: Basic <client_id:client_secret>   (or Bearer <admin_token>)
Content-Type: application/x-www-form-urlencoded

token=<access_or_refresh_token>
token_type_hint=access_token   (optional)
```

Active token:

```json
{
  "active": true,
  "sub": "<pairwise_sub>",
  "scope": "openid email",
  "client_id": "<client_id>",
  "exp": 1234567890,
  "iat": 1234567800,
  "jti": "<uuid>",
  "token_type": "Bearer"
}
```

Anything else — expired, tampered, revoked, unknown, wrong audience:

```json
{ "active": false }
```

**Layering:**

1. **Service seam** — new method on `internal/oidc.Service`:

   ```go
   func (s *Service) Introspect(ctx context.Context, token, clientID string) (IntrospectionResult, error)
   ```

   It classifies the token (JWT vs refresh token), verifies JWT signatures
   against the active signers/JWKS, consults the `RevocationFilter` bloom
   filter (DB-confirming via `RevokedJTIChecker` only on a filter hit — the
   fast path stays stateless), looks refresh tokens up in the session store
   (`revoked_at` / `expires_at`), and enforces cross-client isolation: unless
   the caller is admin, the token's `aud` must match `clientID` or the result
   collapses to inactive.

2. **Handler** — new `internal/oidcapi/introspect.go` with
   `func (s *Server) PostIntrospect(w http.ResponseWriter, r *http.Request)`.
   It authenticates the caller (Basic client credential or admin Bearer;
   anonymous → `401`), parses the form body, delegates to
   `svc.Introspect(...)`, and shapes the response. All negative outcomes
   return `200 { "active": false }` — never a distinguishing status code.

3. **OpenAPI wiring** — `api/` already carries `/introspect` stubs; wire the
   generated route to `PostIntrospect` and reconcile the
   `IntrospectionResponse` schema, regenerating `internal/gen/openapi/`.

No new migrations: the endpoint reads the existing sessions and
`revoked_jtis` tables.

## Non-Goals

- Opaque access token *issuance* (§3.3 opt-in) — introspection will handle
  opaque tokens once issuance exists (1:1 DB-row lookup), but issuance is a
  separate plan.
- Rate limiting — per-client rate limiting on `/introspect` is owned by the
  `rate-limiting` plan (which already lists `/introspect` as a protected
  endpoint); this change only notes the gap.
- Token revocation (`/revoke`, RFC 7009) — separate surface, separate plan.
- Introspection response signing (JWT-secured introspection responses,
  RFC 9701) — plain JSON per RFC 7662 is sufficient.

## Success Criteria

- [ ] `POST /introspect` served on harbor-hot, present in the OpenAPI spec
      and discovery-adjacent docs
- [ ] Valid, non-revoked JWT access token → `active: true` with `sub`,
      `scope`, `client_id`, `exp`, `iat`, `jti`, `token_type` — with **no DB
      hit** when the bloom filter misses
- [ ] Expired or signature-invalid JWT → `{ "active": false }`
- [ ] Revoked JTI (bloom hit + DB confirm) → `{ "active": false }`
- [ ] Refresh token resolved via session store; revoked/expired sessions →
      `{ "active": false }`
- [ ] Cross-client introspection (token `aud` ≠ caller `client_id`, non-admin)
      → `{ "active": false }`, HTTP 200 — indistinguishable from an unknown
      token
- [ ] Admin Bearer token can introspect any token
- [ ] Anonymous caller → `401`
- [ ] `go build ./... && go vet ./... && go test ./...` green;
      `openspec validate token-introspection --strict` passes
