# Proposal: linkerd-mtls (T2.3 Infra Hardening — East-West mTLS)

## Why

Harbor's infra-hardening plan (docs/plans/infra-hardening.md) identifies **no east-west mTLS** as a significant remaining gap: pod-to-pod traffic between `harbor-hot`↔PostgreSQL and `harbor-mgmt`↔Redis is currently unencrypted inside the cluster node. This means a compromised workload on the same node can observe plaintext database credentials and session tokens on the wire.

Linkerd's sidecar-based mTLS closes this gap with zero application-code changes: the CNI plugin and proxy-injector intercept all TCP egress/ingress, establish mutually-authenticated TLS between every meshed pod pair, and emit verifiable mTLS edges.

## What

Deploy Linkerd service mesh on the single-node RKE2 cluster to provide automatic mTLS for all pod-to-pod traffic in the `harbor` namespace.

### Deliverables

| File | Purpose |
|------|---------|
| `deploy/linkerd/values-linkerd-crds.yaml` | Helm values for `linkerd-crds` chart install |
| `deploy/linkerd/values-linkerd-control-plane.yaml` | Helm values for `linkerd/linkerd` control-plane |
| `deploy/linkerd/trust-manager-bundle.yaml` | trust-manager Bundle distributing trust anchor to all namespaces |
| `deploy/linkerd/identity-issuer-cert.yaml` | cert-manager Certificate for Linkerd identity issuer (auto-rotated) |
| `deploy/linkerd/harbor-namespace-injection.yaml` | Namespace patch: `linkerd.io/inject=enabled` on `harbor` |
| `deploy/linkerd/postgres-opaque-ports.yaml` | Service patches: opaque-ports on PostgreSQL (5432) and Redis (6379) |
| `deploy/linkerd/kustomization.yaml` | Kustomize manifest listing all resources |
| `docs/plans/linkerd-mtls.md` | Install order, cert-manager prereqs, verification, rollback |

## Non-goals

- HA control plane (single-node cluster; `ha: false`)
- Linkerd multicluster / federation
- Application code changes (zero-touch injection via namespace annotation)
- Service mesh for workloads outside the `harbor` namespace
- Linkerd policy resources (AuthorizationPolicy / MeshTLSAuthentication) — separate feature
- Replacing existing Calico NetworkPolicies (Linkerd mTLS complements, not replaces, L3/L4 policies)
