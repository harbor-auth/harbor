---
title: Token introspection (RFC 7662 — POST /introspect)
status: draft
design_refs: [§3.3, §3.5, §3.5.2]
targets: [internal/oidcapi/, api/openapi/harbor.yaml, internal/gen/openapi/]
promoted_to: null
openspec: changes/token-introspection
created: 2026-07-14
---

# Token introspection (plan)

> **Dependency order:** depends on **`real-token-issuance`** (access tokens
> must be real JWTs or opaque tokens to introspect meaningfully). No other
> hard prerequisites — can land in Phase 1, parallel to `signing-key-rotation`.
> `bloom-filter-revocation` references introspection as the false-positive
> confirmation path; that plan can prototype without it, but a production
> bloom filter needs this endpoint to avoid wrongly blocking valid tokens.

## Problem

The `bloom-filter-revocation` plan specifies that when a bloom filter check
returns a hit (possible revocation), the RP (or Harbor itself) should
**confirm via token introspection** before rejecting the token, because bloom
filters have false-positive rates. Without an introspection endpoint there is
no confirmation path: either the bloom filter causes spurious rejections
(false positives block real users) or the false-positive fallback is silently
dropped (weakening the revocation guarantee).

Additionally, some RPs cannot or do not want to verify tokens locally
(especially opaque access tokens, §3.3 opt-in). RFC 7662 introspection gives
these RPs a standards-compliant token validation path.

The endpoint is also a privacy-sensitive surface: it reveals token validity
and associated metadata (scope, sub, exp) to the caller. Callers must be
authenticated as registered clients — anonymous introspection is not permitted.

## Proposed approach

### Endpoint contract (RFC 7662)

```
POST /introspect
Authorization: Basic <client_id:client_secret>   (or Bearer <admin_token>)
Content-Type: application/x-www-form-urlencoded

token=<access_or_refresh_token>
token_type_hint=access_token   (optional)
```

Response (active token):
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

Response (inactive / expired / revoked):
```json
{ "active": false }
```

### Implementation

1. **OpenAPI first** — add `POST /introspect` to `api/openapi/harbor.yaml`
   with Basic auth (registered client credential) or admin Bearer token.
   Regenerate `internal/gen/openapi/harbor.gen.go`.

2. **Caller authentication** — introspection callers must present a valid
   client credential (Basic auth with `client_id` + `client_secret`, or an
   admin-scoped Bearer token). Anonymous callers receive `401`. This prevents
   token enumeration by unauthenticated parties.

3. **Token lookup strategy:**
   - **JWT access tokens** — verify signature against JWKS; if valid, return
     `active: true` with the decoded claims. If expired or signature fails,
     return `active: false`. No DB hit for non-revoked tokens (stays on the
     stateless hot path).
   - **Revocation check** — additionally consult the bloom filter (when
     available) or the session store to confirm the token hasn't been
     explicitly revoked. If revoked, return `active: false` even if the
     signature is valid and `exp` is in the future.
   - **Refresh tokens** — look up in the session store (DB); return active
     status from session `revoked_at` / `expires_at`.

4. **Handler** — new `internal/oidcapi/introspect.go`; registered on the
   hot-path router (or management router — see risk note below).

5. **Bloom filter integration** — when `bloom-filter-revocation` ships, the
   introspection handler should check the filter first (fast path: false means
   definitely active; true triggers a DB confirmation). Until then, skip the
   filter check.

### Privacy controls

Per RFC 7662 §4, the introspection response must only reveal claims to
authorized callers. Specifically:

- A client may only introspect tokens it issued (i.e. its own `client_id`
  must match the token's `aud`). Cross-client introspection returns
  `active: false` (no information leakage).
- Admin tokens can introspect any token (for audit/support tooling).

## DESIGN alignment

Realizes §3.3 (opaque access token validation path for RPs that can't verify
JWTs locally) and §3.5 / §3.5.2 (bloom filter false-positive confirmation,
active revocation check). No DESIGN changes needed — §3.3 already documents
introspection as the confirmation path for opaque tokens.

## Target code paths

- `api/openapi/harbor.yaml` — add `POST /introspect` + `IntrospectionResponse` schema
- `internal/gen/openapi/harbor.gen.go` — regenerated
- `internal/oidcapi/introspect.go` — new handler
- `internal/oidcapi/router.go` — register route
- `internal/oidc/` — add revocation-check seam (consulted by introspection)

## Implementation checklist

- [ ] `@openspec new token-introspection` — draft the OpenAPI change
- [ ] Add `POST /introspect` to `api/openapi/harbor.yaml`; regenerate
- [ ] Implement caller authentication (Basic auth client credential check)
- [ ] Implement `internal/oidcapi/introspect.go` — JWT verify + revocation check + response
- [ ] Enforce cross-client isolation (`aud` must match introspecting `client_id`)
- [ ] Register route; verify `go build ./...` clean
- [ ] Tests: valid JWT → `active: true` with claims; expired JWT → `active: false`; revoked session → `active: false`; wrong `client_id` → `active: false` (not 403); anonymous caller → `401`
- [ ] Author & verify paired OpenSpec change: `openspec validate token-introspection --strict`
- [ ] Reconcile & promote: `@plan promote token-introspection`

## Risks & open questions

- **Hot path vs. management router** — introspection is a latency-sensitive
  per-request operation (called by RPs on every API call if they can't verify
  locally). It should live on `harbor-hot`, not `harbor-mgmt`. Document this
  explicitly; the management router has different SLA guarantees.
- **Rate limiting** — introspection is a DB hit for refresh tokens and a
  potential bloom filter hit for access tokens. Without rate limiting, an RP
  (or attacker) can enumerate token validity. Add per-client rate limiting on
  this endpoint as part of the eventual `rate-limiting` plan; note the gap here.
- **Opaque access tokens** — §3.3 mentions opaque tokens as a future opt-in.
  This plan's JWT-first implementation will work correctly for opaque tokens
  once opaque issuance is wired (the opaque token value maps 1:1 to a DB row;
  introspection just looks it up). No blocking dependency.

## Definition of done

`go build/vet/test ./...` green; `POST /introspect` in the OpenAPI spec and
served on `harbor-hot`; JWT-valid active tokens return claims; expired,
tampered, and revoked tokens return `{ "active": false }`; cross-client
isolation enforced; anonymous callers rejected; `make agent-check` clean.
