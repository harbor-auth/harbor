---
title: Token revocation endpoint (RFC 7009 — POST /revoke)
status: draft
design_refs: [§3.5, §3.5.2, §7.4]
targets: [internal/oidcapi/, api/openapi/harbor.yaml, internal/gen/openapi/, internal/oidc/]
promoted_to: null
openspec: changes/token-revocation-endpoint
created: 2026-07-21
---

# Token revocation endpoint (plan)

> **Dependency order (HARD):** build **after** `token-introspection` **and**
> `rate-limiting` are on `main`. `/revoke` shares the `internal/oidcapi/`
> hot-path router/middleware surface that `token-introspection` extends, and it
> is an abuse-sensitive surface that MUST sit **behind the rate limiter** (an
> unthrottled `/revoke` is a token-enumeration and denial-of-service vector).
> The correct build order for the hot-path chain is
> **`token-introspection` → `rate-limiting` → `token-revocation-endpoint`**,
> one at a time, to avoid three plans fighting over the same router files.

## Problem

Harbor has shipped an entire **internal** revocation stack — `revocation-outbox`
(§3.5, §10), `grant-id-fk`, `bloom-filter-revocation`, and the
`internal/oidc/revocation_filter.go` seam — but exposes **no standard,
client-facing RFC 7009 `POST /revoke` endpoint**. This asymmetry means a
Relying Party cannot ask Harbor to revoke a token it holds (e.g. on user
logout, on suspected compromise, or when decommissioning): the machinery to
*record* and *enforce* a revocation exists, but there is no public contract to
*request* one. It is the cheapest, highest-conformance-value item on the board —
almost pure wiring of shipped seams to a standard contract — and closes the
internal/external revocation gap that OIDF/OAuth conformance expects.

## Proposed approach

### Endpoint contract (RFC 7009)

```
POST /revoke
Authorization: Basic <client_id:client_secret>
Content-Type: application/x-www-form-urlencoded

token=<access_or_refresh_token>
token_type_hint=refresh_token   (optional: access_token | refresh_token)
```

Per RFC 7009 the response is **`200 OK` with an empty body for every
well-formed, authenticated request** — including a token that is unknown,
already expired, or already revoked. This uniform success response is a
**deliberate anti-enumeration control**: it denies a caller any signal about
whether a given token value ever existed. Only malformed requests (`400
invalid_request`) and unauthenticated callers (`401`) deviate.

### Implementation

1. **OpenAPI first** — add `POST /revoke` to `api/openapi/harbor.yaml` (Basic
   client auth; `application/x-www-form-urlencoded` body: `token`,
   optional `token_type_hint`; `200` empty success). Regenerate
   `internal/gen/openapi/`.
2. **Caller authentication** — the caller MUST present a valid registered
   client credential (Basic auth), reusing the same client-auth seam as
   `token-introspection`. Anonymous callers get `401`.
3. **Revoke via the shipped stack** — the handler translates a `token` into its
   grant/JTI and drives the **existing** revocation path:
   - **Refresh tokens** — mark the session/grant revoked in the store
     (`revoked_at`), reusing the `grant-id-fk` / session-store seam; the whole
     grant family is invalidated (refresh-token-rotation already models this).
   - **Access tokens (JWT)** — record the JTI in the revocation stack
     (`revocation-outbox` → `revoked_jtis`) so the bloom filter
     (`revocation_filter.go`) and `/introspect` subsequently report the token
     inactive.
4. **Cross-client isolation** — a client may only revoke tokens bound to its
   own `client_id` (`aud`/grant owner match). A token belonging to another
   client yields the **same `200`** (no `403`, no information leak) but performs
   no revocation — mirroring the introspection isolation rule.
5. **Handler** — new `internal/oidcapi/revoke.go`, registered on the hot-path
   router **behind the rate-limiter middleware** (hard dependency above).

**Alternatives considered.** *Put `/revoke` on `harbor-mgmt` (cold path)* —
rejected: RFC 7009 is a client-facing OAuth endpoint RPs call directly; it
belongs next to `/token` and `/introspect` on `harbor-hot`, and reuses their
client-auth + router middleware. *Return `404`/`400` for unknown tokens* —
rejected: it violates RFC 7009 and re-introduces the enumeration oracle the
uniform `200` exists to close. *Synchronously delete state inline* — rejected:
the shipped `revocation-outbox` is the durable, replica-safe path; `/revoke`
feeds it rather than bypassing it.

## DESIGN alignment

Realises §3.5 / §3.5.2 (token revocation and the bloom-filter confirmation
path) and §7.4 (revocation as a security control). It reuses shipped machinery
and adds no new revocation *mechanism* — only the standard client-facing
*contract* — so it does **not** change `DESIGN.md`. The endpoint's placement on
the stateless hot path is consistent with §4.1 (revocation *recording* is a
write; token *verification* stays DB-free via the bloom filter).

## Target code paths

- `api/openapi/harbor.yaml` — add `POST /revoke` (RFC 7009 request/response).
- `internal/gen/openapi/` — regenerated from the contract.
- `internal/oidcapi/revoke.go` — new handler (client auth, token→grant/JTI,
  drive the revocation stack, uniform `200`).
- `internal/oidcapi/server.go` — register `/revoke` behind the rate limiter.
- `internal/oidc/` — reuse the revocation seam (outbox / revoked-JTI / session
  `revoked_at`); add a thin `Revoke(token)` service method if one does not
  already exist.

## Implementation checklist

- [ ] Confirm the hard deps are on `main`: `token-introspection` (shared router + client-auth seam) and `rate-limiting` (the limiter `/revoke` sits behind). Do NOT start until both are merged.
- [ ] `@openspec new token-revocation-endpoint` — draft the OpenAPI change.
- [ ] Add `POST /revoke` to `api/openapi/harbor.yaml` (Basic auth; form body `token` + optional `token_type_hint`; `200` empty success); regenerate `internal/gen/openapi/`.
- [ ] Implement client Basic-auth (reuse the `token-introspection` client-auth seam); anonymous → `401`.
- [ ] Implement `internal/oidcapi/revoke.go`: resolve `token` (honouring `token_type_hint`) → grant/JTI; revoke refresh tokens via the session/grant store (`revoked_at`, whole family); record access-token JTIs via the `revocation-outbox` → `revoked_jtis` seam.
- [ ] Enforce cross-client isolation: a token not owned by the authenticated `client_id` returns the same `200` and performs no revocation (no `403`, no leak).
- [ ] Return **`200` empty body** for well-formed authenticated requests even for unknown/expired/already-revoked tokens (RFC 7009 anti-enumeration); `400 invalid_request` only for malformed requests.
- [ ] Register `/revoke` on the hot-path router **behind the rate-limiter middleware**.
- [ ] Tests: valid refresh token → revoked (session `revoked_at` set; family invalidated); valid access token → JTI recorded, subsequently `/introspect` reports `active:false`; unknown token → `200` (no error, no state change); cross-client token → `200` + no revocation; anonymous caller → `401`; malformed body → `400`.
- [ ] Tests (security): uniform-`200` timing/response does not distinguish existing vs non-existing tokens (no enumeration oracle).
- [ ] Author & verify paired OpenSpec change: `openspec validate token-revocation-endpoint --strict`
- [ ] Reconcile & promote: `@plan promote token-revocation-endpoint`

## Risks & open questions

- **Ordering hazard** — starting before `token-introspection`/`rate-limiting`
  land will collide on `internal/oidcapi/server.go` and leave `/revoke`
  unthrottled. The dependency blockquote above is load-bearing.
- **Anti-enumeration discipline** — the uniform `200` is a security control,
  not laziness; reviewers must reject any code path that returns a
  distinguishing status/body for unknown vs known tokens.
- **Access-token revocation latency** — revoking a JWT access token relies on
  the bloom filter + outbox propagation; there is an inherent window before
  edge caches/filters converge. Document this (it's the same window
  `bloom-filter-revocation` already accepts) — `/revoke` records durably
  immediately; enforcement is eventually-consistent on the hot path.
- **`token_type_hint` trust** — treat the hint as advisory (try the hinted
  store first, fall back to the other) so a wrong hint never causes a missed
  revocation.

## Definition of done

`go build/vet/test ./...` green; `POST /revoke` in the OpenAPI spec and served
on `harbor-hot` behind the rate limiter; refresh tokens are revoked in the
session/grant store and access-token JTIs recorded via the shipped outbox so
`/introspect` reports them inactive; well-formed authenticated requests always
return `200` (no enumeration oracle); cross-client revocation is a no-op `200`;
anonymous callers get `401`; `make agent-check` clean. Ready to `@plan promote`.
