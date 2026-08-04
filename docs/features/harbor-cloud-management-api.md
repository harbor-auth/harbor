---
title: Harbor Cloud management API
status: implemented
design_refs: [§4, §7.1, §10]
code:  [internal/cloudapi/, cmd/harbor-mgmt/, api/openapi/harbor-cloud.yaml, deploy/helm/]
spec:  [api/openapi/harbor-cloud.yaml]
tests: [internal/cloudapi/]
depends_on: []
plan: null
last_reconciled: 2026-08-04
---

# Harbor Cloud management API

## Summary

An internal, versioned `/admin/v1/*` API that `harbor-mgmt` exposes so the
closed-source Harbor Cloud control plane can provision and manage a
self-hosted-shaped Harbor cluster: mint namespace-scoped sessions, manage
namespace lifecycle, and trigger signing-key rotation. It is a private-path
contract, never reachable from `auth.harborauth.com` — see
[`docs/ARCHITECTURE.md`](../ARCHITECTURE.md#harbor-cloud-management-api-optional-private-path-only)
for the topology and
[`deploy/README.md`](../../deploy/README.md#harbor-cloud-management-api) for
the network/credential controls.

## Behavior (as-built)

- **Auth:** every route requires a short-lived, self-issued `cloudServiceAuth`
  bearer JWT (ES256/EdDSA), verified against `CLOUD_SERVICE_AUTH_PUBLIC_KEY`.
  `aud` must equal `harbor-mgmt-cloudapi`; `scope` must cover the route's
  required scope (`sessions:mint`, `namespaces:read`, `namespaces:write`,
  `keys:rotate`); `jti` is single-use, claimed via a Redis `SETNX`-backed
  replay guard with a TTL bounded by the token's own `exp`. An unconfigured
  trust anchor or an unavailable replay guard fails closed (every request
  rejected). Audience/scope comparisons are constant-time. See
  `INV-CLOUDAPI-SERVICE-AUTH` and `INV-CLOUDAPI-REPLAY-RESISTANT` in
  `invariants/registry.yaml`.
- **Namespace lifecycle:** `POST/GET/DELETE /admin/v1/namespaces[/{id}]`
  require an `Idempotency-Key` header on create/delete. A replayed key with
  the same request body hash returns the stored response verbatim; a
  different hash returns `409 idempotency_key_reused`. Delete is naturally
  idempotent — deleting an absent or already-deleted namespace returns `204`
  every time, never `404`.
- **Session minting:** `POST /admin/v1/sessions` mints a namespace-scoped,
  opaque bearer credential (hash stored, plaintext returned once) with no
  relationship to end-user OIDC/BFF sessions. Presenting a session token
  against a namespace other than the one it was minted for returns
  `403 cross_tenant_forbidden`; an expired session returns
  `410 session_expired`.
- **Key rotation:** `POST /admin/v1/keys/rotate` is a scope-checked proxy to
  harbor-hot's existing, unmodified `POST /admin/keys/rotate` — it reuses the
  tested rotation state machine instead of forking it. The proxy call is
  authenticated toward harbor-hot with `MGMT_HOT_PROXY_TOKEN`, a credential
  distinct from the operator's `ADMIN_API_TOKEN`; harbor-hot's audit log
  attributes the two separately (`credential=operator` vs
  `credential=cloud-proxy`). Key rotation is not part of Harbor Cloud's
  customer self-service surface.
- **Gating & reachability:** the whole surface is inert unless
  `mgmt.cloudIntegration.enabled` is `true` (default `false`), and even when
  enabled is reachable only through a dedicated NodePort behind a private
  WireGuard tunnel, restricted by a NetworkPolicy CIDR allow-list. It is
  mounted only on `harbor-mgmt`; `harbor-hot`'s public listener never imports
  `internal/cloudapi`.

## Interfaces / Endpoints

All under `security: [{cloudServiceAuth: []}]` (`api/openapi/harbor-cloud.yaml`):

- `POST /admin/v1/sessions` — mint a namespace-scoped session (`sessions:mint`).
- `POST /admin/v1/namespaces` — create a namespace (`namespaces:write`).
- `GET /admin/v1/namespaces/{id}` — read a namespace (`namespaces:read`).
- `DELETE /admin/v1/namespaces/{id}` — delete a namespace (`namespaces:write`).
- `POST /admin/v1/keys/rotate` — proxy to harbor-hot's key rotation (`keys:rotate`).

Env vars: `CLOUD_INTEGRATION_ENABLED`, `CLOUD_SERVICE_AUTH_PUBLIC_KEY`,
`MGMT_HOT_PROXY_TOKEN`, `HARBOR_HOT_INTERNAL_URL` (all required together when
cloud integration is enabled; `cmd/harbor-mgmt/main.go` fails fast before
listen if any is missing).

## Code map

| Path | Role |
|---|---|
| `internal/cloudapi/serviceauth.go` | `ServiceAuthVerifier` — JWT parse/verify, scope/audience checks, replay guard, audit events. |
| `internal/cloudapi/namespaces.go` | Namespace create/read/delete handlers + idempotency ledger. |
| `internal/cloudapi/sessions.go` | Namespace-scoped session minting + verification. |
| `internal/cloudapi/keys.go` | `KeysHandler` — proxies key rotation to harbor-hot with `MGMT_HOT_PROXY_TOKEN`. |
| `internal/cloudapi/store.go` | `cloud_namespaces` / `cloud_operations` / `cloud_sessions` persistence. |
| `cmd/harbor-mgmt/cloudapi.go` | Route registration, `cloudAuthorized` scope middleware, rate limiting. |
| `api/openapi/harbor-cloud.yaml` | The shared, Apache-2.0 OpenAPI contract (fixtures-only sharing with harbor-cloud). |
| `db/migrations/0019_cloud_namespaces.*.sql` | Schema for namespaces/operations/sessions. |
| `deploy/helm/templates/{service,networkpolicy,secret,deployment}-mgmt.yaml` | Private NodePort, CIDR allow-list, credential wiring. |

## Security & privacy invariants

- `INV-CLOUDAPI-SERVICE-AUTH` — scoped JWT required; `ADMIN_API_TOKEN` and the
  RFC 7591 initial-access token are never accepted on this surface.
- `INV-CLOUDAPI-REPLAY-RESISTANT` — a token's `jti` is single-use within its
  lifetime; the replay guard fails closed when it cannot answer.
- `INV-CONSTANT-TIME-COMPARE` — the `aud` claim comparison is constant-time.

## Tests

`internal/cloudapi/*_test.go` (unit, per-handler), `contract_test.go` +
`testdata/contract/*.json` (fixture-driven contract tests run against the
real router), and `integration_test.go` (`-tags=integration`, cross-process
over real Postgres/Redis) cover authorized, wrong-audience, missing-scope,
expired, replayed, and cross-tenant requests end-to-end.

## Known gaps / TODOs

None open. Both deploy-wiring follow-ons noted during initial implementation
are resolved: `MGMT_HOT_PROXY_TOKEN` is wired into harbor-hot's own Helm
chart and NetworkPolicy (`deploy/helm/templates/{secret-hot,networkpolicy-hot}.yaml`),
and `internal/mgmtapi`'s host-based region gate exempts the `/admin/v1/*`
prefix (`regionExemptPrefixes` in `internal/mgmtapi/region_middleware.go`) so
Harbor Cloud's WireGuard-sourced requests reach `cloudapi`'s own auth/scope
checks instead of 400ing on an unresolved `Host`.
