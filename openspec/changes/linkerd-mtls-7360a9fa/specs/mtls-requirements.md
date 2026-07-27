# Spec: Linkerd mTLS — Requirements

## ADDED Requirements

### REQ-001 — Linkerd CRDs installed before control plane

**SHALL** install the `linkerd-crds` Helm chart before the `linkerd/linkerd`
control-plane chart. CRD resources MUST be present and `Established` before
the control plane starts.

**Scenario:**
- Given: a cluster with no Linkerd CRDs
- When: `helm upgrade --install linkerd-crds linkerd/linkerd-crds -n linkerd` runs
- Then: all Linkerd CRDs are `Established` in the cluster

### REQ-002 — cert-manager manages the identity issuer certificate

**SHALL** use cert-manager to provision and auto-rotate the Linkerd identity
issuer certificate. The cert-manager `Certificate` resource MUST:
- have `duration` ≤ 48h and `renewBefore` ≥ 25h
- be stored as a `kubernetes.io/tls` Secret named `linkerd-identity-issuer`
- reference a ClusterIssuer that is subordinate to the Linkerd trust anchor CA

**Scenario:**
- Given: cert-manager is installed and a `ClusterIssuer` for the trust anchor exists
- When: the `identity-issuer-cert.yaml` manifest is applied
- Then: cert-manager issues a Certificate into `linkerd-identity-issuer` Secret

### REQ-003 — trust-manager distributes trust anchor to all namespaces

**SHALL** configure a trust-manager `Bundle` that reads the Linkerd trust anchor
from the `linkerd` namespace and distributes it as a ConfigMap named
`linkerd-identity-trust-roots` to all namespaces.

**Scenario:**
- Given: trust-manager is installed and the trust anchor Secret exists in `linkerd`
- When: the `trust-manager-bundle.yaml` manifest is applied
- Then: a ConfigMap `linkerd-identity-trust-roots` appears in every namespace

### REQ-004 — Linkerd control plane uses kubernetes.io/tls issuer scheme

**SHALL** set `identity.issuer.scheme=kubernetes.io/tls` in the Linkerd
control-plane Helm values so the identity controller reads the issuer
cert+key from the cert-manager-managed Secret.

**Scenario:**
- Given: `linkerd-identity-issuer` Secret exists (issued by cert-manager)
- When: Linkerd control plane starts with `identity.issuer.scheme=kubernetes.io/tls`
- Then: `linkerd check` passes all identity checks

### REQ-005 — harbor namespace is annotated for Linkerd injection

**SHALL** apply the annotation `linkerd.io/inject=enabled` to the `harbor`
namespace so that all pod deployments in that namespace automatically receive
the Linkerd proxy sidecar.

**Scenario:**
- Given: Linkerd is installed with the proxy injector running
- When: the `harbor-namespace-injection.yaml` patch is applied
- Then: new pods in `harbor` namespace receive a `linkerd-proxy` container

### REQ-006 — PostgreSQL and Redis Services annotated with opaque ports

**SHALL** annotate the `harbor-postgresql` Service with
`config.linkerd.io/opaque-ports=5432` and the `harbor-redis-master` Service
with `config.linkerd.io/opaque-ports=6379` to prevent Linkerd from
attempting protocol detection on server-speaks-first protocols.

**Scenario:**
- Given: Linkerd proxy sidecars are injected into harbor pods
- When: `harbor-hot` connects to `harbor-postgresql:5432`
- Then: the connection succeeds and `linkerd viz edges -n harbor` shows the edge as secured

### REQ-007 — HA disabled for single-node cluster

**SHALL** set `ha: false` (or equivalent per-component `replicaCount: 1`)
in the Linkerd control-plane Helm values. MUST NOT enable
`PodDisruptionBudget` resources that require multiple replicas.

### REQ-008 — Resource limits set on control-plane components

**SHALL** set CPU and memory requests/limits on all Linkerd control-plane
components to prevent unbounded resource consumption on the single-node cluster.

### REQ-009 — Install runbook documented

**SHALL** provide `docs/plans/linkerd-mtls.md` covering:
- Prerequisites (cert-manager, trust-manager)
- Exact Helm install commands in dependency order
- Verification steps (`linkerd check`, `linkerd viz edges`)
- Rollback procedure
