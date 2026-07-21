---
title: UserInfo Endpoint (OIDC Core §5.3 — GET /userinfo)
status: implemented
design_refs: [§3.3, §11.4, §3.1]
code:  [internal/oidcapi/, api/openapi/harbor.yaml, internal/gen/openapi/]
spec:  [api/openapi/harbor.yaml]
tests: [internal/oidcapi/]
depends_on: [real-token-issuance, user-enrollment]
plan: userinfo-endpoint
last_reconciled: 2026-07-20
---

# UserInfo Endpoint (OIDC Core §5.3 — GET /userinfo)

## Summary

Harbor serves `GET /userinfo` (OIDC Core §5.3): a Bearer-authenticated endpoint
that validates a self-issued RFC 9068 JWT access token against the region's
ES256 signing keys and returns the pairwise `sub` (PPID) it carries. The
endpoint is stateless — it verifies the token signature against the live JWKS
rather than doing a DB lookup (§3.3) — and is scope-gated so it never emits PII
beyond the consented scopes (§3.2, §6.5). It closes the OIDC Basic OP
certification requirement that unblocked the green conformance suite.

## Behavior (as-built)

**Bearer extraction** — `bearerToken` parses `Authorization: Bearer <token>`
(case-insensitive scheme per RFC 6750 §2.1). A missing/malformed header yields
`401` with `WWW-Authenticate: Bearer error="invalid_token"`.

**Signature verification** — `Server.verifyAccessToken` verifies the access
token's ES256 signature against this region's signing keys before any claim is
trusted; an invalid/expired token yields `401 invalid_token`. Only the claims
needed to identify the subject are decoded (`iss`, `sub`, `scope`).

**Response** — on success the handler returns `openapi.UserInfoResponse` with
the pairwise `Sub` and `Cache-Control: no-store` / `Pragma: no-cache`. The
response is scope-gated: `email`/`email_verified` are only ever attached when
the `email` scope was granted.

## Interfaces / Endpoints

- `GET /userinfo` (harbor-hot) — `operationId: getUserInfo`; Bearer auth;
  `200` → `UserInfoResponse`; `401` on missing/invalid token.
- Discovery advertises `userinfo_endpoint` in
  `/.well-known/openid-configuration`.
- Exported Go surface: `oidcapi.Server.GetUserInfo`; generated
  `openapi.UserInfoResponse`.

## Code map

| Path | Role |
|---|---|
| `internal/oidcapi/userinfo.go` | `GetUserInfo` handler — Bearer parse, ES256 verify, scope gate, `sub` response. |
| `api/openapi/harbor.yaml` | `GET /userinfo` operation + `UserInfoResponse` schema + `userinfo_endpoint` discovery field. |
| `internal/gen/openapi/harbor.gen.go` | Generated types/handlers for the endpoint. |

## Security & privacy invariants

- **Signature-verified, stateless (§3.3)** — the token's ES256 signature is
  verified against the live JWKS before any claim is trusted; no DB hit on the
  hot path.
- **Pairwise `sub` only (§3.2)** — the returned subject is the PPID; no
  cross-RP-correlatable identifier is emitted.
- **Scope-gated PII (§6.5)** — `email`/`email_verified` are attached only when
  the `email` scope was granted; otherwise only `sub` is returned.
- **No caching** — `Cache-Control: no-store` + `Pragma: no-cache` on every
  response.

## Tests

`internal/oidcapi/userinfo_test.go`:

- Valid access token → `200` with the correct `sub`.
- Missing / malformed Authorization header → `401 invalid_token`.
- Invalid / bad-signature / expired token → `401 invalid_token`.

## Known gaps / TODOs

- **Email resolution** — the `email`/`email_verified` claims are scope-gated but
  not yet populated: the handler currently returns only `sub` (there is a
  `TODO(userinfo)` to resolve the address from the consent grant keyed by
  `sub`). The OIDF suite validates the `sub` round-trip and the scope-gating
  contract, which this satisfies; grant-backed email lookup follows
  [client-grant-persistence](client-grant-persistence.md).
- **Opaque access tokens** — only JWT-format access tokens are supported;
  opaque-token support arrives with the `token-introspection` plan.
