# Harbor — Infrastructure Hardening Plan

> **Authored:** 2026-07-23 · **Target cluster:** `51.89.98.90` (`ns31170412`)
> · RKE2 v1.35.6 · single-node · Calico CNI · ArgoCD GitOps
>
> **Bottom line:** the cluster has solid L3/L4 micro-segmentation and enforces
> Kubernetes Pod Security Admission at the `restricted` profile, but has **no
> east-west mTLS, no policy-as-code, no etcd encryption, and no audit logging.**
> For an internet-facing OIDC/auth service these are meaningful gaps.

---

## Current Security Posture

### ✅ What is already in place

| Control | Detail |
|---|---|
| **Calico NetworkPolicies** | Every workload has an explicit L3/L4 policy: `harbor-hot`, `harbor-mgmt`, `harbor-postgresql`, `harbor-redis`, and all ArgoCD components. Pods may only communicate with explicitly whitelisted peers and ports. |
| **Pod Security Admission — `restricted`** | The `harbor` namespace enforces `pod-security.kubernetes.io/enforce: restricted` (latest). Prevents privileged containers, host-network/PID access, and requires explicit securityContexts. |
| **TLS at ingress** | cert-manager + Cloudflare DNS-01 wildcard certificate on `auth.harborauth.com`. Traffic from the internet is TLS-terminated at the nginx ingress. |
| **Calico CNI** | RKE2 ships with Calico, which enforces NetworkPolicy at kernel level via iptables/eBPF. `clusternetworkpolicies.policy.networking.k8s.io` CRD is present (Calico GlobalNetworkPolicy support). |
| **Admission webhooks** | cert-manager and nginx admission webhooks only — no policy engine yet. |
| **ArgoCD GitOps** | All cluster state is managed declaratively; ad-hoc `kubectl apply` changes are detected and reconciled away. |

### ❌ Gaps

| Gap | Risk |
|---|---|
| **No etcd encryption at rest** | Kubernetes Secrets (`harbor-hot-secrets`, `harbor-mgmt-secrets`, Cloudflare token) are base64-only in etcd — readable by anyone with etcd access or a backup. |
| **No audit logging** | Zero tamper-evident record of API server actions — cannot detect credential theft, privilege escalation, or Secret exfiltration after the fact. |
| **Unrestricted egress** | `harbor-hot` and `harbor-mgmt` pods currently have no egress NetworkPolicy — they can reach any IP on any port. An exploited pod can exfiltrate data or phone home freely. |
| **No east-west mTLS** | Pod-to-pod traffic (hot↔postgres, mgmt↔redis) is unencrypted plaintext inside the node. An attacker with node access or a compromised pod can read DB queries and session data. |
| **No policy-as-code** | No Kyverno or OPA Gatekeeper — no enforcement of image signing, image digest pinning, resource limits, or label requirements. A misconfigured ArgoCD manifest can deploy a `latest`-tagged image from an untrusted registry. |
| **No workload identity (SPIFFE)** | Services authenticate to each other by IP address. No cryptographic proof that the caller is the expected workload. |
| **No runtime threat detection** | No Falco or equivalent — no alerting on anomalous syscalls (e.g. shell spawned inside `harbor-hot`). |

---

## Hardening Roadmap

### Tier 1 — Quick wins (low effort, high value, no downtime)

**Do this week.**

#### T1.1 — etcd encryption at rest

**What:** Encrypts all Kubernetes Secrets in etcd using AES-CBC. One config
line; requires a rolling `rke2-server` restart (seconds of API unavailability,
pods keep running).

**How:**
```yaml
# /etc/rancher/rke2/config.yaml (append)
encrypt: true
```
```bash
systemctl restart rke2-server
kubectl get secrets -A  # verify secrets re-encrypt on next write
```

**Impact:** Cloudflare DNS token, `HARBOR_KMS_SECRET`, `DATABASE_URL`,
`REDIS_URL` are no longer recoverable from an etcd backup or snapshot.

---

#### T1.2 — Kubernetes API audit logging

**What:** Records every API server action (reads, writes, deletes) in a
tamper-evident append-only log on disk. Essential for post-incident forensics
and compliance (`user-audit-trail` in the app covers application-level events;
this covers cluster-level events).

**How:** Add to `/etc/rancher/rke2/config.yaml`:
```yaml
kube-apiserver-arg:
  - "audit-log-path=/var/lib/rancher/rke2/server/logs/audit.log"
  - "audit-log-maxage=30"
  - "audit-log-maxbackup=5"
  - "audit-log-maxsize=100"
  - "audit-policy-file=/etc/rancher/rke2/audit-policy.yaml"
```

Create `/etc/rancher/rke2/audit-policy.yaml`:
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all Secret reads and writes at Request level
  - level: Request
    resources:
      - group: ""
        resources: ["secrets"]
  # Log all writes in the harbor namespace at RequestResponse level
  - level: RequestResponse
    namespaces: ["harbor"]
    verbs: ["create", "update", "patch", "delete"]
  # Log everything else at Metadata level (no body, just who/what/when)
  - level: Metadata
```

Then: `systemctl restart rke2-server`.

---

#### T1.3 — Calico default-deny egress

**What:** Add egress NetworkPolicies to `harbor-hot` and `harbor-mgmt` that
whitelist only the destinations they actually need. Currently both pods have
**unrestricted egress** — they can connect to any IP on any port.

**Allowed egress per service:**

| Pod | Allowed egress destinations |
|---|---|
| `harbor-hot` | `harbor-postgresql:5432`, `harbor-redis:6379`, DNS (kube-dns:53), `0.0.0.0/0:443` (HTTPS for Cloudflare KMS / JWKS external fetch) |
| `harbor-mgmt` | `harbor-redis:6379`, DNS, `0.0.0.0/0:443` (SMTP relay for email) |

**How:** Add egress rules to the existing Helm NetworkPolicy templates in
`deploy/helm/templates/`. ArgoCD will apply on next sync.

---

### Tier 2 — Medium effort, significant gain

**Do this month.**

#### T2.1 — Linkerd mTLS (east-west encryption)

**What:** Linkerd is a lightweight service mesh (Rust-based sidecar proxy) that
transparently mTLS-encrypts all pod-to-pod traffic. Zero application code
changes required — it works by injecting a sidecar via a namespace annotation.

**Why Linkerd over Istio:** Linkerd adds ~1ms p99 latency per hop and ~25 MB
RAM per pod (vs Istio/Envoy at 10–30ms p99 and ~50+ MB). For a latency-sensitive
auth service, Linkerd is the right choice.

**Overhead assessment:**
- p50 latency added: < 1ms per hop
- p99 latency added: ~3–7ms per hop
- RAM per pod: ~20–30 MB
- Control plane: ~150–200 MB total (3 pods)
- Not perceptible given DB query (5–15ms) and signing (~1ms) already dominate

**How:**
```bash
# Install Linkerd CRDs and control plane
linkerd install --crds | kubectl apply -f -
linkerd install | kubectl apply -f -
linkerd check  # wait for green

# Enable injection for the harbor namespace
kubectl annotate namespace harbor linkerd.io/inject=enabled

# Rolling restart to inject sidecars
kubectl rollout restart deployment -n harbor
```

**Verification:**
```bash
linkerd viz install | kubectl apply -f -
linkerd viz dashboard &  # check mTLS edges between harbor pods
```

**Integration with cert-manager:** Linkerd uses its own internal CA by default.
For production, configure it to use a cert-manager-issued intermediate CA so
the trust root is managed consistently with the rest of the cluster.

---

#### T2.2 — Kyverno policy-as-code

**What:** Kyverno is a Kubernetes-native policy engine that validates, mutates,
and generates resources at admission time. It enforces cluster standards without
requiring Rego knowledge (unlike OPA Gatekeeper).

**Why Kyverno over OPA Gatekeeper:** Kyverno uses native Kubernetes YAML for
policies — no Rego DSL to learn, simpler to audit, better docs.

**Install:**
```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm install kyverno kyverno/kyverno -n kyverno --create-namespace \
  --set replicaCount=1  # single-node; scale to 3 in prod
```

**Priority policies to implement:**

| Policy | Mode | Rule |
|---|---|---|
| `disallow-latest-tag` | `Enforce` | Block any Pod spec using `:latest` image tag |
| `require-image-digest` | `Audit` (then Enforce) | Require images to be pinned by digest (SHA256) |
| `require-resource-limits` | `Enforce` | All containers must declare CPU and memory limits |
| `disallow-privilege-escalation` | `Enforce` | Belt-and-suspenders over PSA `restricted` |
| `require-harbor-labels` | `Audit` | All harbor-namespace Pods must have `app.kubernetes.io/name` and `app.kubernetes.io/version` |

---

### Tier 3 — Longer-term hardening

**Future work — not blocking production launch.**

#### T3.1 — Image signing with Cosign + Kyverno

**What:** Sign Docker images in CI with Cosign (part of the Sigstore stack);
add a Kyverno `verifyImages` policy that blocks pods using unsigned images.
Ensures supply chain integrity — only images built by the Harbor CI pipeline
can run.

**Prerequisites:** T2.2 (Kyverno), GitHub Actions secret for Cosign key or
Sigstore keyless signing.

---

#### T3.2 — Falco runtime threat detection

**What:** Falco monitors kernel-level syscalls and fires alerts on anomalous
behavior: shell spawned in a production container, unexpected outbound
connection, `/etc/passwd` read, etc. Complements network controls with
in-process detection.

**Deploy via Helm:**
```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco -n falco --create-namespace \
  --set driver.kind=modern_ebpf  # eBPF driver, no kernel module needed
```

---

#### T3.3 — SPIFFE/SPIRE workload identity

**What:** SPIRE issues X.509 SVIDs (SPIFFE Verifiable Identity Documents) to
each pod based on its Kubernetes service account. This gives workloads
cryptographic identity that the application can verify — not just IP-based trust.
Useful when Harbor expands to multi-region and services need to authenticate to
each other across region boundaries without a shared secret.

**Prerequisite:** T2.1 (Linkerd) can integrate with SPIRE as its identity
backend, giving both mTLS *and* app-accessible SVIDs.

---

#### T3.4 — WireGuard node-to-node encryption (Calico)

**What:** Calico can encrypt the overlay network between nodes with WireGuard.
Currently single-node so all pod traffic stays on loopback — WireGuard adds
nothing yet. When a second node is added, enable with:

```bash
kubectl patch felixconfiguration default --type='merge' \
  -p '{"spec":{"wireguardEnabled":true}}'
```

---

## Implementation Order

```
Week 1:   T1.1 etcd encryption (5 min)
          T1.2 audit logging (15 min)
          T1.3 Calico egress deny (30 min, Helm change + ArgoCD sync)

Week 2:   T2.1 Linkerd mTLS

Week 3:   T2.2 Kyverno + policies

Later:    T3.1 Cosign image signing
          T3.2 Falco
          T3.3 SPIFFE/SPIRE (if/when multi-region)
          T3.4 WireGuard (when second node added)
```

---

## Relationship to Application-Level Hardening

This plan covers **infrastructure** controls only. It complements but does not
replace the application-level security work tracked in
[`production-readiness.md`](production-readiness.md):

- `admin-endpoint-auth` (P0) — unauthenticated `/admin` endpoints on `harbor-hot`
- `client-secret-auth` (P0) — no client secret verification on `/token`
- `hsm-signing-key` (P1) — ephemeral in-process signing keys
- `user-audit-trail` (P1) — application-level audit log

Both layers are required. Infrastructure controls (this doc) defend the platform;
application controls defend the protocol. Neither substitutes for the other.

---

> **Anti-drift note:** when a Tier-1 or Tier-2 item is completed, strike it
> here and note the completion date — same discipline as `production-readiness.md`.
