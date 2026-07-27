# Plan — Linkerd mTLS East-West Encryption (`linkerd-mtls`)

> **Status:** draft · **Tier:** T2.3 (infra-hardening) · **Target:** `harbor` namespace on
> `51.89.98.90` (RKE2, Calico, PSA `restricted`) · **Parent doc:** [`infra-hardening.md`](infra-hardening.md#t23--linkerd-mtls-east-west-encryption)

## 1. Problem statement

All pod-to-pod traffic inside the cluster is **plaintext**: `harbor-hot ↔ PostgreSQL`
(user rows, consent, token grants), `harbor-hot/mgmt ↔ Redis` (enrollment sessions,
revocation state), `mgmt ↔ postgres`. Calico NetworkPolicies give L3/L4 *segmentation*
but not *encryption or workload identity* — any process that gains node-level packet
capture (container escape, malicious DaemonSet, compromised kubelet) reads credentials
and PII off the wire. For an OIDC provider whose product *is* trust, unencrypted
east-west traffic is a material gap, and several compliance frameworks (SOC 2, ISO
27001 A.8.24) expect encryption in transit internally, not just at the edge.

Linkerd gives transparent mTLS with per-pod cryptographic identity, zero app changes,
and ~1ms p99 added per hop (vs Istio's 10–30ms) — the right trade for a
latency-sensitive auth hot path where DB queries (5–15ms) already dominate.

## 2. Approach

### 2.1 Deliverables (in-repo)

```
deploy/linkerd/
  values-linkerd-crds.yaml       # linkerd-crds chart values (mostly empty, pinned version)
  values-linkerd-control-plane.yaml  # external issuer, single-node tolerations, resources
  values-trust-manager.yaml      # trust-manager (cert-manager project) values
  cert-manager-issuers.yaml      # trust anchor + identity-issuer Certificate/Issuer chain
  trust-bundle.yaml              # trust-manager Bundle distributing the anchor
  kustomization.yaml
  README.md                      # install order, verification, rollback runbook
deploy/helm/templates/…          # chart changes: namespace inject annotation,
                                 # opaque-ports on postgres/redis Services (see 2.3)
```

### 2.2 Identity: cert-manager + trust-manager, NOT the default self-signed CA

Linkerd's default `linkerd install` generates a self-signed trust anchor with no
rotation story (issuer cert expires silently ⇒ full-mesh outage). We instead use the
**two-tier CA with external management** from day one:

1. **Trust anchor (root):** cert-manager `Certificate` (self-signed bootstrap Issuer,
   10y, `isCA: true`) in `cert-manager` namespace → Secret `linkerd-trust-anchor`.
2. **Identity issuer (intermediate):** cert-manager `Certificate` (48h duration,
   `renewBefore: 25h`, `isCA: true`, issued by a CA Issuer pointing at the anchor) →
   Secret `linkerd-identity-issuer` in `linkerd` namespace, `kubernetes.io/tls` scheme.
3. **trust-manager `Bundle`:** distributes the anchor's CA cert as ConfigMap
   `linkerd-identity-trust-roots` into the `linkerd` namespace (and any future ones).
4. Helm values: `identity.issuer.scheme: kubernetes.io/tls` and
   `identity.externalCA: true` so the control plane consumes both externally-managed
   objects; cert-manager rotates the intermediate every ~24h **with zero downtime**.

This also plugs into T3.1 (cert-expiry alerting): the issuer cert is a normal
cert-manager Certificate exposed in `certmanager_certificate_expiration_timestamp_seconds`.

### 2.3 Meshing Harbor + opaque ports (the critical correctness detail)

- Namespace annotation `linkerd.io/inject: enabled` added to
  `deploy/helm/templates/namespace.yaml` (and mirrored in `deploy/k8s/namespace.yaml`),
  **gated behind a values flag** (`linkerd.enabled`, default `false`) so the chart still
  deploys on clusters without Linkerd and rollback is a one-line values flip.
- **PostgreSQL and Redis are server-speaks-first protocols.** Linkerd's protocol
  detection waits for client-first bytes and would stall/misclassify them. Their
  Services get `config.linkerd.io/opaque-ports: "5432"` / `"6379"` annotations —
  proxied as raw mTLS TCP, no protocol detection. Forgetting this causes connection
  timeouts; it ships in the same commit as the inject annotation, never separately.
- Rollout: annotate → `kubectl rollout restart deployment -n harbor` (proxies inject
  at pod creation).

### 2.4 Cluster fit — RKE2 / Calico / PSA / NetworkPolicy interactions

- **PSA `restricted` on `harbor`:** the default `linkerd-init` initContainer needs
  `NET_ADMIN`/`NET_RAW` — **not allowed** under restricted. Use the **linkerd-cni
  DaemonSet** (`values: cniEnabled: true` + linkerd2-cni chart) so iptables rewiring
  happens at the CNI level and injected pods stay `restricted`-compliant. This is the
  single most important compatibility decision; CNI plugin chains after Calico.
- **Existing NetworkPolicies:** proxy traffic keeps original pod IPs, but the egress
  policies on harbor-hot/mgmt must additionally allow: proxy → `linkerd` namespace
  :8080/:8086 (identity/destination/policy APIs) and :4191/:4190 admin/inbound ports on
  the ingress side for probes. Update `networkpolicy-hot.yaml` / `networkpolicy-mgmt.yaml`
  accordingly, and add an ingress allowance for kubelet probes to :4191.
- **Single node:** control-plane HA off (`controllerReplicas: 1`), modest resource
  requests; ~200 MB total control plane + ~25 MB/pod is acceptable.
- Ingress → hot: nginx (kube-system, unmeshed) still connects over plaintext TLS-terminated
  hop inside the node to the meshed pod's inbound proxy; acceptable for phase 1, note as
  follow-up to mesh or re-point ingress.

## 3. Implementation steps

1. `deploy/linkerd/cert-manager-issuers.yaml`: bootstrap SelfSigned Issuer → trust
   anchor Certificate → CA Issuer → 48h identity-issuer Certificate.
2. `deploy/linkerd/values-trust-manager.yaml` + `trust-bundle.yaml` (Bundle → ConfigMap
   `linkerd-identity-trust-roots`).
3. `deploy/linkerd/values-linkerd-control-plane.yaml`: external issuer scheme, CNI
   enabled, single-replica, pinned chart version.
4. Chart edits: `linkerd.enabled` values flag; namespace inject annotation; opaque-ports
   annotations on `service-hot/mgmt` (n/a) and the **postgres/redis Services** (these are
   deployed outside the chart — ship a `deploy/linkerd/patch-opaque-ports.yaml` kustomize
   patch + document the `kubectl annotate` equivalents in README).
5. NetworkPolicy updates for proxy control-plane egress + probe ingress.
6. README runbook: exact Helm install order (`linkerd-crds` → `linkerd-cni` →
   `linkerd-control-plane` → trust-manager), `linkerd check` gates between each,
   meshing rollout, verification, and rollback (`linkerd.enabled=false` + rollout
   restart un-meshes without uninstalling).

## 4. Validation

- `helm lint deploy/helm` green with `linkerd.enabled` both true and false;
  `helm template … | kubectl apply --dry-run=client -f -` clean.
- `kubectl apply --dry-run=client -f deploy/linkerd/` clean for raw manifests.
- On-cluster (operator runbook): `linkerd check` fully green post-install;
  `linkerd viz edges po -n harbor` shows **all edges `√ secured`**;
  `linkerd viz tap` on hot→postgres shows opaque TCP with mTLS identity
  `harbor-postgresql.harbor.serviceaccount.identity.linkerd.cluster.local`.
- Functional smoke: full OIDC flow (authorize → token → userinfo) green post-mesh;
  p99 latency delta < 5ms on the token endpoint.
- Rotation drill: `cert-manager renew` the identity issuer → `linkerd check --proxy`
  stays green, no connection resets.
- Repo checks: `go build ./... && go vet ./... && go test ./... && make agent-check` green.
