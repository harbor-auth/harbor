# Proposal: Token revocation endpoint (RFC 7009 — POST /revoke)

## Problem

Harbor has shipped a complete **internal** revocation stack — `revocation-outbox`
(§3.5, §10), `grant-id-fk`, `bloom-filter-revocation`, and the
`internal/oidc/revocation_filter.go` seam — but exposes **no standard,
client-facing RFC 7009 `POST /revoke` endpoint**. A Relying Party therefore
cannot ask Harbor to revoke a token it holds (logout, suspected compromise,
decommissioning): the machinery to record and enforce a revocation exists, but
there is no public contract to request one. This internal/external asymmetry is
an OAuth/OIDF conformance gap and is the cheapest high-value item to close —
almost pure wiring of shipped seams to a standard contract.

## Proposed Solution

Add `POST /revoke` on `harbor-hot`, OpenAPI-first, behind the rate limiter:

1. **Contract** — add `POST /revoke` to `api/openapi/harbor.yaml` (Basic client
   auth; `application/x-www-form-urlencoded` body: `token`, optional
   `token_type_hint`; `200` empty success). Regenerate `internal/gen/openapi/`.
2. **Client authentication** — the caller MUST present a valid registered client
   credential (Basic auth), reusing the `token-introspection` client-auth seam;
   anonymous callers get `401`.
3. **Revoke via the shipped stack** — resolve `token` → grant/JTI: refresh
   tokens are marked revoked in the session/grant store (`revoked_at`, whole
   family) via the `grant-id-fk` seam; access-token JTIs are recorded through
   the `revocation-outbox` → `revoked_jtis` path so the bloom filter and
   `/introspect` subsequently report them inactive.
4. **Uniform 200 (anti-enumeration)** — every well-formed, authenticated request
   returns `200` with an empty body, including unknown/expired/already-revoked
   tokens and tokens owned by another client (no revocation performed, but the
   same `200`, no `403`). Only malformed requests get `400 invalid_request`.
5. **Placement** — new `internal/oidcapi/revoke.go`, registered on the hot-path
   router **behind the rate-limiter middleware**.

## Non-Goals

- Any new revocation *mechanism* — this change reuses the shipped stack and adds
  only the standard client-facing contract.
- Synchronous edge-cache/bloom-filter convergence — access-token enforcement
  remains eventually-consistent on the hot path (the window `bloom-filter-
  revocation` already accepts); `/revoke` records durably immediately.
- Placing `/revoke` on `harbor-mgmt` (it is a client-facing OAuth endpoint).
- Rate-limiting itself (provided by the `rate-limiting` change this sits behind).

## Success Criteria

- [ ] `POST /revoke` in `api/openapi/harbor.yaml`; `internal/gen/openapi/` regenerated.
- [ ] Client Basic-auth enforced (anonymous → `401`).
- [ ] Refresh-token revocation sets `revoked_at` and invalidates the grant family.
- [ ] Access-token revocation records the JTI via the shipped outbox → `/introspect` reports `active:false`.
- [ ] Well-formed authenticated requests return `200` empty for unknown/expired/already-revoked tokens.
- [ ] Cross-client token → `200`, no revocation, no `403`/leak.
- [ ] Malformed request → `400 invalid_request`.
- [ ] `/revoke` registered behind the rate-limiter middleware.
- [ ] `make agent-check` clean.
