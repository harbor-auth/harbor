# Design: linkerd-mtls

## Architecture Decisions

### D1 — trust-manager for trust anchor distribution (not Linkerd default)

The Linkerd default trust anchor distribution requires manually copying the CA
certificate into every namespace. Instead, we use
[cert-manager/trust-manager](https://cert-manager.io/docs/projects/trust-manager/)
`Bundle` CRD which automatically propagates the Linkerd trust anchor ConfigMap
(`linkerd-identity-trust-roots`) to all namespaces. This eliminates manual
per-namespace cert propagation and keeps the source of truth in cert-manager.

### D2 — identity.issuer.scheme=kubernetes.io/tls

The Linkerd identity issuer Certificate is managed by cert-manager and stored
as a `kubernetes.io/tls` Secret. Setting `identity.issuer.scheme=kubernetes.io/tls`
tells the Linkerd identity controller to read the issuer cert+key from that
Secret directly, enabling cert-manager's automatic rotation to flow through
without any manual Linkerd restarts.

### D3 — HA=false on single-node cluster

The production cluster is a single RKE2 node (`ns31170412`). Running Linkerd
in HA mode (3 replicas of each control-plane component) would be wasteful and
would fail PodDisruptionBudget scheduling. `ha: false` is set explicitly.
Scale to `ha: true` when the cluster gains ≥3 nodes.

### D4 — Opaque ports for PostgreSQL (5432) and Redis (6379)

PostgreSQL and Redis are **server-speaks-first** protocols: the server sends
bytes immediately on connection before the client says anything. Linkerd's
transparent proxy cannot detect the protocol and will attempt TLS negotiation
first, breaking the connection. Setting `config.linkerd.io/opaque-ports` on
the Service objects tells Linkerd to treat these ports as opaque TCP (no
protocol detection), passing the raw bytes through while still wrapping the
connection in mTLS at the transport layer.

### D5 — Linkerd viz for edge verification

`linkerd viz` is installed as a separate Helm release. Its `edges` subcommand
shows which pod pairs have established mTLS, providing the primary verification
signal during and after rollout.

### D6 — Namespace-level injection (not pod-level)

The `linkerd.io/inject=enabled` annotation is applied to the `harbor`
namespace rather than individual pod specs. This ensures ALL workloads in
the namespace (including future ones) are automatically meshed, and avoids
per-Deployment annotation churn.

## Component Relationships

```
cert-manager (existing)
  └─ Certificate: linkerd-identity-issuer
       └─ issues into: Secret linkerd-identity-issuer (ns: linkerd)
trust-manager (existing)
  └─ Bundle: linkerd-trust-anchor
       └─ distributes: ConfigMap linkerd-identity-trust-roots → all namespaces

Linkerd control plane (new)
  ├─ linkerd-crds chart (CRDs first)
  └─ linkerd/linkerd chart
       ├─ reads identity issuer from: Secret linkerd-identity-issuer
       └─ reads trust anchor from: ConfigMap linkerd-identity-trust-roots

harbor namespace
  ├─ Namespace annotation: linkerd.io/inject=enabled
  ├─ Service harbor-postgresql: opaque-ports=5432
  └─ Service harbor-redis-master: opaque-ports=6379
```

## File Layout

```
deploy/linkerd/
├── kustomization.yaml              # Kustomize entry point
├── values-linkerd-crds.yaml        # Helm values: linkerd-crds chart
├── values-linkerd-control-plane.yaml  # Helm values: linkerd control-plane
├── trust-manager-bundle.yaml       # trust-manager Bundle CRD
├── identity-issuer-cert.yaml       # cert-manager Certificate
├── harbor-namespace-injection.yaml # Namespace annotation patch
└── postgres-opaque-ports.yaml      # Service annotation patches
docs/plans/
└── linkerd-mtls.md                 # Plan + install runbook
```

## Install Order

1. CRDs first: `helm upgrade --install linkerd-crds linkerd/linkerd-crds`
2. cert-manager Certificate + trust-manager Bundle
3. Wait for trust anchor to propagate
4. Linkerd control plane
5. Namespace injection annotation
6. Opaque port Service patches
7. Rolling restart of harbor pods
8. Verify: `linkerd viz edges -n harbor`
