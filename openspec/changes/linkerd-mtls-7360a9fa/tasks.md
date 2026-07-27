# Tasks: linkerd-mtls

## Prerequisites

- cert-manager installed in the cluster (`cert-manager` namespace)
- trust-manager installed in the cluster
- Linkerd Helm repo added: `helm repo add linkerd https://helm.linkerd.io/stable`
- `kubectl` access to the RKE2 cluster

## Implementation

### T1 — Create docs/plans/linkerd-mtls.md (plan + install runbook)

Author the plan file covering: purpose, architecture decisions (D1–D6),
prerequisites, install order, verification steps, and rollback procedure.

**Files:** `docs/plans/linkerd-mtls.md`

### T2 — Create Helm values for linkerd-crds chart

Create `deploy/linkerd/values-linkerd-crds.yaml` with minimal values for the
`linkerd-crds` Helm chart (typically empty or minimal metadata).

**Files:** `deploy/linkerd/values-linkerd-crds.yaml`

### T3 — Create Helm values for linkerd control-plane chart

Create `deploy/linkerd/values-linkerd-control-plane.yaml` with:
- `identity.issuer.scheme: kubernetes.io/tls`
- `ha: false`
- Resource requests/limits on control-plane components
- `clusterNetworks` matching the RKE2 cluster CIDR

**Files:** `deploy/linkerd/values-linkerd-control-plane.yaml`

### T4 — Create cert-manager Certificate and trust-manager Bundle

Create:
- `deploy/linkerd/identity-issuer-cert.yaml` — cert-manager Certificate for
  the identity issuer (duration 48h, renewBefore 25h, secretName
  `linkerd-identity-issuer`, namespace `linkerd`)
- `deploy/linkerd/trust-manager-bundle.yaml` — trust-manager Bundle CRD
  distributing `linkerd-identity-trust-roots` ConfigMap to all namespaces

**Files:** `deploy/linkerd/identity-issuer-cert.yaml`, `deploy/linkerd/trust-manager-bundle.yaml`

### T5 — Create namespace injection and opaque-ports patches

Create:
- `deploy/linkerd/harbor-namespace-injection.yaml` — strategic merge patch
  annotating the `harbor` namespace with `linkerd.io/inject=enabled`
- `deploy/linkerd/postgres-opaque-ports.yaml` — strategic merge patches
  annotating `harbor-postgresql` with `config.linkerd.io/opaque-ports=5432`
  and `harbor-redis-master` with `config.linkerd.io/opaque-ports=6379`

**Files:** `deploy/linkerd/harbor-namespace-injection.yaml`, `deploy/linkerd/postgres-opaque-ports.yaml`

### T6 — Create deploy/linkerd/kustomization.yaml

Create the Kustomize manifest listing all resources in `deploy/linkerd/`.

**Files:** `deploy/linkerd/kustomization.yaml`

## Validation

- `helm lint deploy/linkerd/` (if helm is available in CI)
- `kubectl apply --dry-run=client -k deploy/linkerd/` (on cluster: dry-run validation)
- `openspec validate linkerd-mtls-7360a9fa --strict`
- `go build ./... && go vet ./... && go test ./... && make agent-check` (no Go changes expected; verify no regressions)
