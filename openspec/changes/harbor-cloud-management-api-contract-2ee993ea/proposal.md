## Why

Harbor Cloud (the closed-source SaaS control plane, `harbor-auth/harbor-cloud`)
needs to mint management sessions, provision/deprovision namespaces, and
trigger signing-key rotation against a self-hosted Harbor core cluster. No
such contract exists today: harbor-mgmt has zero routes for this integration
(only a disabled `mgmt.cloudIntegration` NodePort/NetworkPolicy scaffold), and
harbor-hot's existing `/admin/keys/rotate` is reachable only by an operator
holding `ADMIN_API_TOKEN` — a coarse, unscoped, non-expiring shared secret
that must never be handed to an external SaaS control plane. Building this
without a formal contract risks either an unauthenticated internal surface or
reuse of a bootstrap/operator credential across a trust boundary.

## What Changes

- New `internal/cloudapi` package, wired into `cmd/harbor-mgmt/main.go` only,
  registered behind the existing `mgmt.cloudIntegration` gate (private
  WireGuard-backed NodePort). Never reachable from harbor-hot's public
  listener or the public ingress host.
- Versioned routes `POST /admin/v1/sessions`, `POST /admin/v1/namespaces`,
  `GET /admin/v1/namespaces/{id}`, `DELETE /admin/v1/namespaces/{id}`,
  `POST /admin/v1/keys/rotate` (proxies to harbor-hot's existing, unchanged
  `/admin/keys/rotate` over a second, distinct internal credential —
  `/admin/keys/rotate` itself is preserved as-is for operators).
- A new scoped service-JWT auth layer (ES256/EdDSA, `aud`/`sub`/`scope`/`exp`/
  `jti`), Redis-backed replay resistance, constant-time verification,
  fail-closed config, audit events, and per-route rate limits — entirely
  separate from `ADMIN_API_TOKEN` and the RFC 7591 initial-access token.
- Idempotency-key contract for namespace create/delete and session minting,
  with stable machine-readable error codes.
- `api/openapi/harbor-cloud.yaml` (Apache-2.0) plus JSON fixtures as the
  shared, importable-free contract with harbor-cloud.

## Capabilities

### New Capabilities

- `harbor-cloud-management-api`: the authenticated internal contract harbor
  core exposes to harbor-cloud for session minting, namespace lifecycle, and
  signing-key rotation.

## Impact

Affected: `internal/cloudapi/` (new), `cmd/harbor-mgmt/main.go`,
`internal/oidcapi/admin_auth.go` (second internal credential),
`db/migrations/0019_*` (new), `api/openapi/harbor-cloud.yaml` (new),
`deploy/helm/`, `deploy/k8s/`, `invariants/registry.yaml`,
`docs/design/architecture/`, `deploy/README.md`. No production credentials or
DNS changes; Helm/K8s defaults keep `cloudIntegration.enabled: false`.

## Non-goals

- Harbor Cloud's own implementation (proprietary, out of this repo).
- mTLS/OIDC operator SSO for the existing `/admin/keys/rotate` operator path.
- Any customer/tenant self-service exposure of key rotation.
- Multi-region namespace replication (single-region provisioning only).
