# Plan — Linkerd mTLS East-West Encryption (`linkerd-mtls`)

> **Status:** in-progress · **Tier:** T2.3 (infra-hardening) · **Target:** `harbor` namespace on
> `51.89.98.90` (RKE2 v1.35.6, Calico CNI, PSA `restricted`) · **Parent doc:** [`infra-hardening.md`](infra-hardening.md#t23--linkerd-mtls-east-west-encryption)

## 1. Purpose

All pod-to-pod traffic inside the cluster is **plaintext**: `harbor-hot ↔ PostgreSQL`
(user rows, consent, token grants), `harbor-hot/mgmt ↔ Redis` (enrollment sessions,
revocation state), `mgmt ↔ postgres`. Calico NetworkPolicies give L3/L4 *segmentation*
but not *encryption or workload identity* — any process that gains node-level packet
capture (container escape, malicious DaemonSet, compromised kubelet) reads credentials
and PII off the wire.

For an OIDC provider whose product *is* trust, unencrypted east-west traffic is a
material gap, and several compliance frameworks (SOC 2, ISO 27001 A.8.24) expect
encryption in transit internally, not just at the edge.

Linkerd gives transparent mTLS with per-pod cryptographic identity, zero application
changes, and ~1ms p99 added per hop (vs Istio's 10–30ms) — the right trade for a
latency-sensitive auth hot path where DB queries (5–15ms) already dominate.

## 2. Architecture decisions

### 2.1 cert-manager + trust-manager, NOT the Linkerd default self-signed CA

Linkerd's default `linkerd install` generates a self-signed trust anchor with no
rotation story: the identity issuer cert expires silently after the configured
duration, causing a full-mesh outage with no alerting. We use the **two-tier CA with
external management** from day one:

| Layer | Tool | Duration | Namespace |
|---|---|---|---|
| Trust anchor (root CA) | cert-manager `Certificate` (bootstrap SelfSigned Issuer) | 10y | `cert-manager` |
| Identity issuer (intermediate CA) | cert-manager `Certificate` (issued by CA Issuer backed by the anchor) | 48h, renew at 25h | `linkerd` |
| Trust bundle distribution | trust-manager `Bundle` | synced continuously | all namespaces |

Helm values: `identity.issuer.scheme: kubernetes.io/tls` and `identity.externalCA: true`
so the control plane reads from the externally-managed `linkerd-identity-issuer` Secret;
cert-manager rotates the intermediate every ~24h **with zero downtime**.

This also plugs into T3.1 (cert-expiry alerting): the issuer cert is a normal
cert-manager Certificate exposed in `certmanager_certificate_expiration_timestamp_seconds`.

### 2.2 HA=false on a single-node cluster

`controllerReplicas: 1` (and similarly for destination, proxy-injector, etc.). Running
3 replicas on a single node wastes ~450 MB RAM and provides zero availability gain —
all replicas would fail simultaneously with the node. Scale to `controllerReplicas: 3`
when a second node is added.

### 2.3 Opaque ports for PostgreSQL and Redis (REQUIRED)

PostgreSQL and Redis are **server-speaks-first** protocols: the server sends data before
the client. Linkerd's protocol detection waits for client-first bytes, which causes it
to stall or misclassify these connections, leading to connection timeouts.

The Services for `harbor-postgresql` and `harbor-redis-master` **must** carry:
- `config.linkerd.io/opaque-ports: "5432"` (PostgreSQL)
- `config.linkerd.io/opaque-ports: "6379"` (Redis)

Opaque ports are proxied as raw mTLS TCP with no protocol detection. Forgetting this
annotation causes connection errors that appear immediately after rolling the namespace
with injection enabled; it ships in the same commit as the inject annotation, never
separately.

### 2.4 Linkerd CNI plugin (required for PSA `restricted`)

The default `linkerd-init` initContainer requires `NET_ADMIN`/`NET_RAW` capabilities —
**not permitted** under PSA `restricted` enforced on the `harbor` namespace. The
**Linkerd CNI DaemonSet** (`linkerd2-cni` chart) rewires iptables at the CNI level so
injected pods need no elevated capabilities and remain `restricted`-compliant.

CNI plugin chains **after Calico** via `/etc/cni/net.d/` ordering — this is the default
and requires no special config. This is the single most important compatibility decision
for this cluster.

### 2.5 NetworkPolicy updates required

Linkerd proxies keep the original pod IPs, so existing Calico NetworkPolicies continue
to control pod-to-pod L3/L4 routing. However, the following additional allowances are
needed (see `deploy/helm/templates/networkpolicy-hot.yaml` and `networkpolicy-mgmt.yaml`):

| Traffic | Port | Direction | Reason |
|---|---|---|---|
| harbor pods → `linkerd` namespace | 8080 (identity), 8086 (destination/policy) | egress | proxy control-plane APIs |
| kubelet → harbor pods | 4191 (proxy admin), 4190 (proxy inbound) | ingress | liveness/readiness probes |

## 3. In-repo deliverables

```
deploy/linkerd/
  values-linkerd-crds.yaml            # linkerd-crds Helm chart values (pinned version)
  values-linkerd-control-plane.yaml   # control plane: external issuer, CNI, HA=false, resource caps
  trust-manager-bundle.yaml           # trust-manager Bundle: distribute anchor to all namespaces
  identity-issuer-cert.yaml           # cert-manager Certificate for the identity issuer (48h)
  harbor-namespace-injection.yaml     # Namespace annotation patch: linkerd.io/inject=enabled
  postgres-opaque-ports.yaml          # Service annotation patches: opaque-ports for PG + Redis
  kustomization.yaml                  # kustomize root for deploy/linkerd/
  README.md                           # install order, cert-manager prereqs, verification, rollback
```

The trust anchor Certificate and bootstrap Issuer live in the `cert-manager` namespace
and are provisioned as part of the cert-manager/trust-manager installation (see §4.2).

## 4. Prerequisites

### 4.1 cert-manager (must be installed first)

cert-manager must be installed and healthy before Linkerd is deployed. The identity
issuer Certificate will not be issued until cert-manager is ready.

```bash
# Check if cert-manager is already installed:
kubectl get deploy -n cert-manager

# If not installed:
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version v1.16.x \
  --set crds.enabled=true

kubectl rollout status deploy -n cert-manager
kubectl wait --for=condition=Available deploy --all -n cert-manager --timeout=120s
```

### 4.2 Trust anchor and bootstrap Issuer (cert-manager resources)

Before installing Linkerd, provision the two-tier CA chain. These resources are
committed under `deploy/linkerd/identity-issuer-cert.yaml` (the full chain):

```bash
# Apply the Issuer chain and Certificates (trust anchor + identity issuer):
kubectl create namespace linkerd --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f deploy/linkerd/identity-issuer-cert.yaml

# Wait for both Certificates to be Ready:
kubectl wait --for=condition=Ready certificate/linkerd-trust-anchor \
  -n cert-manager --timeout=60s
kubectl wait --for=condition=Ready certificate/linkerd-identity-issuer \
  -n linkerd --timeout=60s
```

### 4.3 trust-manager

trust-manager distributes the Linkerd trust anchor bundle as a ConfigMap
(`linkerd-identity-trust-roots`) into all namespaces, so each Linkerd proxy can
validate peer certificates without a direct Secret read.

```bash
helm install trust-manager jetstack/trust-manager \
  --namespace cert-manager \
  --version v0.12.x \
  --set app.webhook.tls.approveSignerNames[0]="clusterissuers.cert-manager.io/*" \
  --wait

# Apply the Bundle that distributes the anchor:
kubectl apply -f deploy/linkerd/trust-manager-bundle.yaml

# Verify the ConfigMap exists in the linkerd namespace:
kubectl get configmap linkerd-identity-trust-roots -n linkerd
```

### 4.4 Linkerd CLI

```bash
# Install the linkerd CLI (version pinned to match chart version):
curl --proto '=https' --tlsv1.2 -sSfL https://run.linkerd.io/install | sh
# or via brew: brew install linkerd

linkerd version --client
# Should print: stable-2.17.x (match to chart version below)
```

## 5. Installation order

Install in this exact dependency order. Each step includes a gate check before
proceeding.

### Step 1 — linkerd-crds

```bash
helm repo add linkerd https://helm.linkerd.io/stable
helm repo update

helm install linkerd-crds linkerd/linkerd-crds \
  --namespace linkerd \
  --create-namespace \
  -f deploy/linkerd/values-linkerd-crds.yaml

# Gate: CRDs must be established before proceeding
kubectl wait --for=condition=Established crd \
  serviceprofiles.linkerd.io \
  httproutes.gateway.networking.k8s.io \
  --timeout=60s
```

### Step 2 — linkerd-cni (required for PSA restricted)

```bash
helm install linkerd-cni linkerd/linkerd2-cni \
  --namespace linkerd-cni \
  --create-namespace

kubectl rollout status daemonset/linkerd-cni -n linkerd-cni
# Gate: all nodes must have the CNI plugin ready
kubectl wait --for=condition=Ready pod -l app=linkerd-cni \
  -n linkerd-cni --timeout=120s
```

### Step 3 — linkerd-control-plane

```bash
helm install linkerd-control-plane linkerd/linkerd-control-plane \
  --namespace linkerd \
  -f deploy/linkerd/values-linkerd-control-plane.yaml

kubectl rollout status deploy -n linkerd
# Gate: full Linkerd check before meshing anything
linkerd check
# All checks must be green (✓) before Step 4
```

### Step 4 — Linkerd viz (for verification)

```bash
linkerd viz install | kubectl apply -f -
kubectl rollout status deploy -n linkerd-viz
linkerd viz check
```

### Step 5 — Apply opaque-port annotations (before meshing)

Annotate Postgres and Redis Services **before** rolling the Harbor namespace, so proxies
are configured correctly from first injection:

```bash
kubectl apply -f deploy/linkerd/postgres-opaque-ports.yaml
# Verify annotations:
kubectl get svc harbor-postgresql harbor-redis-master -n harbor \
  -o jsonpath='{range .items[*]}{.metadata.name}: {.metadata.annotations.config\.linkerd\.io/opaque-ports}{"\n"}{end}'
```

### Step 6 — Enable namespace injection + rollout

```bash
kubectl apply -f deploy/linkerd/harbor-namespace-injection.yaml
# Annotation on the harbor namespace is applied; proxies inject at pod creation.
kubectl rollout restart deployment -n harbor
kubectl rollout status deployment -n harbor
```

## 6. Verification

Run all verification steps after the harbor rollout completes.

### 6.1 Linkerd control-plane check

```bash
linkerd check
# Expect: all checks ✓, zero warnings
```

### 6.2 Proxy check (confirms proxies injected)

```bash
linkerd check --proxy -n harbor
# Expect: all checks ✓ including "data plane proxies are ready"
```

### 6.3 mTLS edge verification

```bash
linkerd viz edges pod -n harbor
# Every edge must show: SECURED  √
# Example expected output:
#  SRC                    DST                  SECURED
#  harbor-hot-xxx         harbor-postgresql-0  √
#  harbor-hot-xxx         harbor-redis-master-0 √
#  harbor-mgmt-xxx        harbor-postgresql-0  √
#  harbor-mgmt-xxx        harbor-redis-master-0 √
```

### 6.4 Opaque TCP tap (confirm no protocol detection stall on PG/Redis)

```bash
linkerd viz tap deploy/harbor-hot -n harbor \
  --to svc/harbor-postgresql -n harbor
# Expect: stream of [tls] entries with opaque scheme, not timeout/error
```

### 6.5 Functional smoke test

```bash
# Full OIDC flow must remain green post-mesh:
# authorize → token → userinfo
# Run against https://auth.harborauth.com — confirm HTTP 200 at each step.
# p99 latency on /token endpoint: delta from pre-mesh baseline should be < 5ms.
```

### 6.6 Rotation drill

```bash
# Force cert-manager to renew the identity issuer:
kubectl annotate certificate linkerd-identity-issuer -n linkerd \
  cert-manager.io/issue-temporary-certificate=true --overwrite

# Linkerd proxies must stay healthy through rotation:
linkerd check --proxy -n harbor
# Expect: all checks ✓, zero connection resets in harbor pod logs
```

### 6.7 Repo checks

```bash
go build ./... && go vet ./... && go test ./... && make agent-check
# All must pass — no Go changes are expected; this confirms no regressions.
```

## 7. Rollback

Rollback is a two-step operation: remove injection, then optionally uninstall the
control plane. Rolling back **does not** require uninstalling cert-manager or trust-manager
(which may be shared with other features).

### 7.1 Remove injection (proxies drain cleanly)

```bash
# Remove the inject annotation from the namespace:
kubectl annotate namespace harbor linkerd.io/inject-

# Roll the harbor deployments to eject proxies:
kubectl rollout restart deployment -n harbor
kubectl rollout status deployment -n harbor

# Verify no linkerd-proxy containers remain:
kubectl get pod -n harbor \
  -o jsonpath='{range .items[*]}{.metadata.name}: {range .spec.containers[*]}{.name} {end}{"\n"}{end}' \
  | grep -v linkerd-proxy
```

### 7.2 Uninstall the Linkerd control plane (optional, if rolling back fully)

```bash
helm uninstall linkerd-viz -n linkerd-viz   2>/dev/null || true
helm uninstall linkerd-control-plane -n linkerd
helm uninstall linkerd-cni -n linkerd-cni
helm uninstall linkerd-crds -n linkerd
```

### 7.3 Remove opaque-port annotations (optional cleanup)

```bash
kubectl annotate svc harbor-postgresql -n harbor \
  config.linkerd.io/opaque-ports-
kubectl annotate svc harbor-redis-master -n harbor \
  config.linkerd.io/opaque-ports-
```

### 7.4 GitOps rollback (preferred)

If deployed via ArgoCD, remove `deploy/linkerd/harbor-namespace-injection.yaml` from
`deploy/linkerd/kustomization.yaml` (or revert the commit that added it) and let ArgoCD
sync. The namespace inject annotation is removed, and the next `kubectl rollout restart
deployment -n harbor` ejects the proxies. The Linkerd control plane itself remains
installed and healthy — only the harbor workloads are un-meshed.
This is the production rollback path — always prefer this over manual annotation removal.

## 8. Risks and open questions

| Risk | Mitigation |
|---|---|
| PSA `restricted` rejects injected pods | CNI plugin (Step 2) eliminates init-container capability requirement; verify with `kubectl describe pod … | grep -A5 Security` |
| Opaque port annotation missed → connection timeout | Apply `postgres-opaque-ports.yaml` in Step 5, **before** the rollout; automated check in `linkerd viz edges` confirms |
| Identity issuer expiry during outage window | cert-manager renews at 25h (before 48h expiry); `linkerd check` surfaces cert issues; T3.1 alerting fires at 14d |
| Single-node control plane restart → brief mTLS gap | Existing connections use cached certs; ~1–2 minute gap acceptable on single-node; HA when second node added |
| NetworkPolicy blocks proxy→control-plane | Update `networkpolicy-hot.yaml` and `networkpolicy-mgmt.yaml` to allow egress on ports 8080/8086 to `linkerd` namespace |
| Nginx ingress (kube-system, unmeshed) → meshed harbor-hot | Ingress still connects over plaintext; acceptable for phase 1; note as follow-up to mesh ingress or re-point |

## 9. Definition of done

- [ ] `linkerd check` fully green (zero warnings) post-install
- [ ] `linkerd check --proxy -n harbor` fully green
- [ ] `linkerd viz edges pod -n harbor` shows all edges `√ secured`
- [ ] `linkerd viz tap` on hot→postgres shows opaque TCP with mTLS identity
- [ ] Full OIDC smoke test (authorize → token → userinfo) passes post-mesh
- [ ] Rotation drill passes (`cert-manager renew` → proxies stay healthy)
- [ ] `go build ./... && go vet ./... && go test ./... && make agent-check` green
- [ ] `helm lint deploy/linkerd/` clean
- [ ] `kubectl apply --dry-run=client -f deploy/linkerd/` clean
- [ ] `infra-hardening.md` T2.3 row updated with completion date
