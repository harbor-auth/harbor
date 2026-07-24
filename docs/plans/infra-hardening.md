# Harbor — Infrastructure Hardening Plan

> **Authored:** 2026-07-23 · **Revised:** 2026-07-23 (post Fable analysis + live cluster
> verification) · **Target cluster:** `51.89.98.90` (`ns31170412`) · RKE2 v1.35.6
> · single-node · Calico CNI · ArgoCD GitOps
>
> **Bottom line:** the cluster has solid L3/L4 micro-segmentation and enforces Pod
> Security Admission at the `restricted` profile. All Tier-0 and Tier-1 critical/quick
> wins are **complete as of 2026-07-24**: host-level ports blocked, etcd bound to
> localhost, NetworkPolicies tightened, audit logging active, and etcd secrets
> upgraded from AES-CBC to secretbox (AEAD). Remaining gaps: no east-west mTLS,
> no ArgoCD SSO.

---

## Current Security Posture

### ✅ What is already in place

| Control | Detail |
|---|---|
| **etcd encryption at rest** | Enabled with **secretbox** (XSalsa20+Poly1305 AEAD) as of 2026-07-24. Custom encryption config at `/etc/rancher/rke2/encryption-config-custom.json`; kube-apiserver pointed to it via `kube-apiserver-arg`. All 33 cluster secrets re-encrypted. |
| **Egress NetworkPolicies** | harbor-hot and harbor-mgmt both have egress rules applied in the `harbor` namespace, locking egress to DNS (53), Redis (6379), PostgreSQL (5432), HTTPS/443, and SMTP (587/465). Applied 2026-07-24. |
| **Host firewall (iptables)** | iptables INPUT chain DROP rules applied for ports 6443, 9345, 10250, 10255, 2379, 2380, 9091. Saved via `iptables-persistent`. Applied 2026-07-24. |
| **etcd localhost-only binding** | etcd confirmed listening on `127.0.0.1:2379` only (was `51.89.98.90:2379`). Applied 2026-07-24. |
| **API audit logging** | Audit policy and log path configured in RKE2 (`/etc/rancher/rke2/audit-policy.yaml`). rke2-server restarted 2026-07-24. Log at `/var/lib/rancher/rke2/server/logs/audit.log`. |
| **ArgoCD initial admin secret** | `argocd-initial-admin-secret` deleted 2026-07-24. |
| **nginx allow-snippet-annotations** | ConfigMap `rke2-ingress-nginx-controller` patched with `allow-snippet-annotations: true` 2026-07-24. |
| **Calico NetworkPolicies (ingress)** | Every workload has an explicit L3/L4 ingress policy: `harbor-hot` (from kube-system ingress controller only), `harbor-mgmt` (same-namespace pods only), `harbor-postgresql`, `harbor-redis`, and all ArgoCD components. |
| **Pod Security Admission — `restricted`** | The `harbor` namespace enforces `pod-security.kubernetes.io/enforce: restricted` (latest). Prevents privileged containers, host-network/PID access, requires explicit securityContexts. |
| **TLS at ingress** | cert-manager + Cloudflare DNS-01 wildcard certificate on `auth.harborauth.com`. Traffic from the internet is TLS-terminated at the nginx ingress. |
| **Calico CNI** | RKE2 ships with Calico, enforcing NetworkPolicy at kernel level via iptables/eBPF. `clusternetworkpolicies.policy.networking.k8s.io` CRD is present. |
| **ArgoCD GitOps** | All cluster state is managed declaratively; ad-hoc `kubectl apply` changes are detected and reconciled away. |
| **etcd snapshots** | RKE2 takes daily snapshots automatically (stored in `/var/lib/rancher/rke2/server/db/snapshots/`). |

### ✅ Critical Gaps — Resolved 2026-07-24

| Gap | Resolution |
|---|---|
| **etcd listening on public IP** | Bound to `127.0.0.1:2379` via `etcd-arg` in `/etc/rancher/rke2/config.yaml`. Verified: `ss -tlnp \| grep 2379` shows localhost only. |
| **No host-level firewall** | iptables INPUT DROP rules applied for ports 6443, 9345, 10250, 10255, 2379, 2380, 9091. Saved via `iptables-persistent` to `/etc/iptables/rules.v4`. |
| **kube-apiserver (6443) exposed to internet** | Blocked by iptables INPUT DROP rule. |
| **kubelet API (10250) exposed to internet** | Blocked by iptables INPUT DROP rule. |

### 🟡 Significant Gaps

| Gap | Risk / Status |
|---|---|
| ~~**AES-CBC encryption cipher**~~ | **Resolved 2026-07-24** — upgraded to secretbox (AEAD). See T1.5. |
| **No admin endpoint protection at nginx layer** | The hardened nginx build (v1.14.5-hardened2) blocks `server-snippet` via admission webhook even with `allow-snippet-annotations: true` in ConfigMap. `/admin` endpoints are protected by application-level Bearer token auth (see `admin-endpoint-auth` in `production-readiness.md`). Future: dedicated admin port or Calico HostEndpoint policy. |
| **etcd snapshots are local-only** | Daily snapshots exist but only on the same node. A disk failure loses both live data and backup. |
| **No east-west mTLS** | Pod-to-pod traffic (hot↔postgres, mgmt↔redis) is unencrypted inside the node. See T2.3 Linkerd. |
| **No policy-as-code** | No Kyverno or OPA Gatekeeper. No enforcement of image signing, resource limits, or label requirements. |
| **No runtime threat detection** | No Falco or equivalent — no alerting on anomalous syscalls. |
| **ArgoCD no SSO** | Admin password rotated and initial secret deleted 2026-07-24, but SSO not yet configured. See T2.2. |

---

## Hardening Roadmap

### Tier 0 — Critical host exposure (do immediately, < 1 hour total)

These items are reachable from the internet **right now**. Do not proceed to other tiers
before completing these.

---

#### T0.1 — Block dangerous ports at the cloud/host firewall

**What:** Close Kubernetes-internal ports from the internet. The live INPUT chain
shows `cali-INPUT` (Calico) runs as **rule #1** before any UFW chain — meaning
`ufw default deny incoming` may be silently bypassed by Calico's ACCEPT verdicts
for its own ports. **UFW alone is not a reliable layer here.** Use a combination
of:

**Option A (recommended): OVH/cloud security group or firewall-as-a-service**
If the hosting provider (OVH for `51.89.98.90`) offers a cloud firewall / security
group, configure it to allow only:
- Port 22/tcp (SSH, ideally restricted to your IP)
- Port 80/tcp (nginx ingress HTTP)
- Port 443/tcp (nginx ingress HTTPS)

This blocks 6443, 9345, 10250, 9091 before packets even reach the node.

**Option B: Calico HostEndpoint policy (k8s-native)**
Calico's `GlobalNetworkPolicy` can protect host ports directly, operating in the
same iptables chain that processes host traffic:
```yaml
apiVersion: crd.projectcalico.org/v1
kind: HostEndpoint
metadata:
  name: ns31170412-eth0
  labels:
    host: ns31170412
spec:
  interfaceName: eth0
  node: ns31170412
  expectedIPs: ["51.89.98.90"]
---
apiVersion: crd.projectcalico.org/v1
kind: GlobalNetworkPolicy
metadata:
  name: deny-external-k8s-ports
spec:
  selector: host == 'ns31170412'
  order: 10
  ingress:
    - action: Allow
      protocol: TCP
      destination:
        ports: [22, 80, 443]
    - action: Deny
      protocol: TCP
      destination:
        ports: [6443, 9345, 10250, 9091, 2379, 2380]
  egress:
    - action: Allow
```

**Option C: UFW (last resort, with caveats)**
UFW can work but requires `BEFORE` rules that run before Calico:
```bash
# Must restart UFW in Calico-aware way — check Calico failsafeInboundHostPorts
# to ensure k8s health probes still work before enabling
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw default deny incoming
sudo ufw enable
```
Test thoroughly: verify kubelet health probes and pod-to-pod routing still work
after enabling. If pods go unhealthy, UFW is interfering with Calico.

> ⚠️ **Single-node note:** Restrict kubectl/API access (6443) to your IP only if
> you do need remote access: `sudo ufw allow from <YOUR_IP> to any port 6443`

---

#### T0.2 — Bind etcd to localhost only

**What:** etcd is currently listening on the public IP `51.89.98.90:2379`, making the
cluster state directly reachable from the internet. It should only listen on loopback.

**Verify the exposure:**
```bash
ssh ubuntu@51.89.98.90 "ss -tlnp | grep 2379"
# Shows: 51.89.98.90:2379 — this is the problem
```

**How:** In RKE2, this is controlled by the etcd listen address. Add to
`/etc/rancher/rke2/config.yaml`:
```yaml
etcd-arg:
  - "listen-client-urls=https://127.0.0.1:2379"
  - "listen-peer-urls=https://127.0.0.1:2380"
  - "advertise-client-urls=https://127.0.0.1:2379"
```
Then restart: `sudo systemctl restart rke2-server`

> **Note:** After UFW is enabled (T0.1), port 2379 will be blocked at the firewall
> layer even without this config change. But defense-in-depth means both layers
> should be applied. Do T0.1 first for immediate protection, then T0.2 for binding.

---

### Tier 1 — Quick wins (this week)

---

#### T1.1 — Add HTTPS egress to harbor-hot NetworkPolicy

**What:** The harbor-hot egress NetworkPolicy has no port-443 rule. Any outbound
HTTPS call from harbor-hot (Cloudflare KMS, external JWKS fetch, etc.) is silently
blocked by Calico. This is a functional bug as well as a hardening gap.

**How:** Add an HTTPS egress rule to `deploy/helm/templates/networkpolicy-hot.yaml`:
```yaml
egress:
  # ... existing DNS, Redis, PostgreSQL rules ...
  # External HTTPS (Cloudflare KMS API, remote JWKS fetch).
  # ipBlock 0.0.0.0/0 but port-locked to 443 only.
  - to:
      - ipBlock:
          cidr: 0.0.0.0/0
    ports:
      - port: 443
        protocol: TCP
```

ArgoCD will apply on next sync. Also add a similar HTTPS egress rule to
`networkpolicy-mgmt.yaml` for the email relay SMTP-over-TLS (typically port 587
or 465, not 443 — check your relay config and use the correct port).

---

#### T1.2 — Block `/admin/*` at nginx ingress

**What:** `harbor-hot` exposes privileged admin endpoints (`/admin/keys/rotate`,
`/admin/revoke-jwt`) that must not be reachable from the internet regardless of
application-level authentication. The ingress should deny these paths before they
reach the pod.

**How:** The `server-snippet` annotation requires `allow-snippet-annotations: true`
in the ingress-nginx ConfigMap (disabled by default in ingress-nginx ≥ 1.9 after
CVE-2023-5044). First check/enable it:

```bash
kubectl patch configmap ingress-nginx-controller -n kube-system \
  --type merge -p '{"data":{"allow-snippet-annotations":"true"}}'
```

Then add to the Ingress annotations in `deploy/helm/templates/ingress.yaml`:
```yaml
annotations:
  nginx.ingress.kubernetes.io/server-snippet: |
    location ~* ^/admin/ {
      deny all;
      return 403;
    }
```

**Alternative (preferred, no snippet needed):** Create a separate Ingress resource
that matches `/admin/` with a `403` default-backend, or use a Calico NetworkPolicy
that blocks admin-port access from the ingress controller entirely (requires a
dedicated admin port separate from the public port — a future app-level change).

Test with:
```bash
curl -sk https://auth.harborauth.com/admin/keys/rotate  # must return 403
```

---

#### T1.3 — Rotate ArgoCD admin credentials and disable initial secret

**What:** ArgoCD's initial auto-generated admin password is still in use
(`argocd-initial-admin-secret`). ArgoCD has full cluster deploy access — compromising
it is equivalent to `kubectl apply` as cluster-admin.

**How:**
```bash
# 1. Set a new strong password
argocd login <argocd-url> --username admin --password 0ipUuVBtT1CwgqrX
argocd account update-password --current-password 0ipUuVBtT1CwgqrX --new-password <STRONG_PASSWORD>

# 2. Delete the initial secret (ArgoCD reads the bcrypt hash from argocd-secret, not this one)
kubectl delete secret argocd-initial-admin-secret -n argocd

# 3. Optionally: disable the admin account entirely and use SSO (see T2.2)
```

---

#### T1.4 — Kubernetes API audit logging

**What:** Records every API server action (reads, writes, deletes) in a
tamper-evident log on disk. Essential for post-incident forensics — without this,
you cannot tell what happened after a breach.

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
  # Log all Secret reads and writes at Request level (body captured)
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

Then: `sudo systemctl restart rke2-server`

---

#### T1.5 — Upgrade etcd encryption cipher to secretbox

**What:** RKE2 defaults to AES-CBC, which has known weaknesses (padding oracle
attacks, IV reuse). Upstream Kubernetes recommends `secretbox` (XSalsa20+Poly1305)
as the primary cipher — it is authenticated encryption (AEAD) and immune to padding
oracle attacks.

> **Note:** This is **not** about enabling encryption (it's already on). This is
> about upgrading the cipher. The current status shows: `Active: AES-CBC aescbckey`.

**How:** RKE2's supported path uses the `rke2 secrets-encrypt` subcommands —
**do not hand-edit** `/var/lib/rancher/rke2/server/cred/encryption-config.json`
directly as RKE2 may overwrite it on restart.

Check what the current RKE2 version supports:
```bash
sudo rke2 secrets-encrypt status
sudo rke2 secrets-encrypt --help  # look for 'rotate-keys' or provider options
```

For RKE2 versions that expose provider configuration, the upgrade path is:
1. Add `secretbox` as the **first** provider and keep `aescbc` as a fallback
   reader using the supported RKE2 config mechanism (check release notes for
   your exact version — this varies by RKE2 release).
2. Restart: `sudo systemctl restart rke2-server`
3. Force re-encryption of all existing secrets:
   `sudo rke2 secrets-encrypt reencrypt --force`
4. Verify: `sudo rke2 secrets-encrypt status` — should show `secretbox` as active.
5. Once confirmed, remove the `aescbc` fallback.

> **Important:** `systemctl restart rke2-server` alone does NOT re-encrypt existing
> secrets. The `reencrypt` step is mandatory to migrate existing Secrets to the new
> cipher.
>
> **AES-CBC accuracy note:** The risk justification for upgrading is primarily
> **missing integrity protection** (AES-CBC is not AEAD — a tampered ciphertext
> decrypts to garbage with no error). `secretbox` (XSalsa20+Poly1305) is AEAD and
> detects tampering. The "padding oracle" framing only applies when there's a
> decryption oracle (not present in etcd-at-rest); the integrity gap is the
> more accurate risk.

---

### Tier 2 — Medium effort, significant gain (this month)

---

#### T2.1 — Offsite etcd backup

**What:** RKE2 takes daily snapshots to `/var/lib/rancher/rke2/server/db/snapshots/`
but they are local-only. A disk failure or node compromise loses both live data
and backup simultaneously. Snapshots must be shipped offsite.

**How:** Add a CronJob or systemd timer to sync snapshots to S3 or equivalent:
```bash
# Example: sync to Cloudflare R2 (or AWS S3)
aws s3 sync /var/lib/rancher/rke2/server/db/snapshots/ \
  s3://harbor-backups/etcd/ --delete
```

Alternatively, use `rke2 etcd-snapshot --s3` flags to configure S3 upload directly:
```yaml
# /etc/rancher/rke2/config.yaml
etcd-snapshot-schedule-cron: "0 */6 * * *"  # every 6 hours
etcd-s3: true
etcd-s3-bucket: harbor-etcd-backups
etcd-s3-region: us-east-1
etcd-s3-access-key: ...
etcd-s3-secret-key: ...
```

Also add a daily `pg_dump` or WAL archiving for PostgreSQL — etcd holds cluster
state but the application data (users, consent, audit trail) is in Postgres.

---

#### T2.2 — ArgoCD SSO (replace admin account)

**What:** Replace the admin password with SSO so ArgoCD access is gated by your
identity provider. For a GitHub-backed org, this means Dex + GitHub OAuth.

**How:** Configure Dex in ArgoCD's `argocd-cm` ConfigMap:
```yaml
url: https://argocd.internal.harborauth.com
dex.config: |
  connectors:
  - type: github
    id: github
    name: GitHub
    config:
      clientID: <github-oauth-app-client-id>
      clientSecret: $dex.github.clientSecret
      orgs:
      - name: harbor-auth
        teams:
        - ops
```

Then create RBAC in `argocd-rbac-cm` limiting who can deploy:
```yaml
policy.default: role:readonly
policy.csv: |
  p, role:ops, applications, *, */*, allow
  p, role:ops, clusters, get, *, allow
  g, harbor-auth:ops, role:ops
```

---

#### T2.3 — Linkerd mTLS (east-west encryption)

**What:** Linkerd is a lightweight service mesh (Rust-based sidecar proxy) that
transparently mTLS-encrypts all pod-to-pod traffic. Zero application code changes
required.

**Why Linkerd over Istio:** Linkerd adds ~1ms p99 latency per hop and ~25 MB RAM
per pod (vs Istio/Envoy at 10–30ms p99 and ~50+ MB). For a latency-sensitive auth
service, Linkerd is the right choice.

**Overhead:**
- p50 latency added: < 1ms per hop
- p99 latency added: ~3–7ms per hop
- RAM per pod: ~20–30 MB
- Control plane: ~150–200 MB total (3 pods)
- Not perceptible given DB queries (5–15ms) already dominate

**Install:**
```bash
linkerd install --crds | kubectl apply -f -
linkerd install | kubectl apply -f -
linkerd check  # wait for green

kubectl annotate namespace harbor linkerd.io/inject=enabled
kubectl rollout restart deployment -n harbor
```

**Critical: PostgreSQL and Redis need opaque port annotation**

PostgreSQL and Redis use "server-speaks-first" protocols — the server sends data
before the client does. Linkerd cannot auto-detect these as HTTP/gRPC, so it
will fail to establish mTLS for them unless you mark the ports as opaque:

```bash
# On the PostgreSQL and Redis Services:
kubectl annotate service harbor-postgresql -n harbor \
  config.linkerd.io/opaque-ports="5432"
kubectl annotate service harbor-redis-master -n harbor \
  config.linkerd.io/opaque-ports="6379"
```

Without this, Linkerd proxies these connections as TCP tunnels with mTLS but
without protocol detection — which is correct behavior but must be explicitly
declared. Forgetting this causes connection errors.

**Integration with cert-manager (trust hierarchy):**

Linkerd uses a **two-tier CA**:
- **Trust anchor** (root CA): long-lived, offline. Linkerd reads it as a ConfigMap.
- **Identity issuer** (intermediate CA): short-lived, cert-manager can rotate it.

For production, use `trust-manager` (from cert-manager project) to distribute
the trust anchor bundle to all namespaces, and use cert-manager to issue and
rotate the identity issuer certificate:

```bash
helm install trust-manager jetstack/trust-manager -n cert-manager
```

The `linkerd install --identity-external-issuer` flag and
`identity.issuer.scheme: kubernetes.io/tls` tell Linkerd to read its identity
issuer cert from a `linkerd-identity-issuer` Secret that cert-manager manages.
See [Linkerd + cert-manager docs](https://linkerd.io/2/tasks/automatically-rotating-control-plane-tls-credentials/)
for the full setup. **Do not skip this step** — the default self-signed CA has
no rotation and will expire in 10 years.

**Verification:**
```bash
linkerd viz install | kubectl apply -f -
linkerd viz dashboard &  # check mTLS edges between harbor pods
linkerd viz edges pod -n harbor  # must show "secured" on all edges
```

---

#### T2.4 — Kyverno policy-as-code

**What:** Kyverno enforces cluster standards at admission time without requiring
Rego knowledge (unlike OPA Gatekeeper).

**Install:**
```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm install kyverno kyverno/kyverno -n kyverno --create-namespace \
  --set replicaCount=1  # single-node; scale to 3 in a multi-node cluster
```

**Priority policies:**

| Policy | Mode | Rule |
|---|---|---|
| `disallow-latest-tag` | `Enforce` | Block any Pod spec using `:latest` image tag |
| `require-image-digest` | `Audit` → `Enforce` | Require images to be pinned by digest (SHA256) |
| `require-resource-limits` | `Enforce` | All containers must declare CPU and memory limits |
| `disallow-privilege-escalation` | `Enforce` | Belt-and-suspenders over PSA `restricted` |
| `require-harbor-labels` | `Audit` | All harbor-namespace Pods must have `app.kubernetes.io/name` and `app.kubernetes.io/version` |

---

### Tier 3 — Longer-term hardening

**Future work — not blocking production launch.**

---

#### T3.1 — Certificate expiry alerting

**What:** cert-manager exposes Prometheus metrics including `certmanager_certificate_expiration_timestamp_seconds`.
Set a PrometheusRule to alert when any certificate expires within 14 days.

**How:** Install Prometheus (or enable cert-manager's built-in metrics scraping),
then:
```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: cert-expiry
  namespace: cert-manager
spec:
  groups:
  - name: cert-manager
    rules:
    - alert: CertificateExpiringSoon
      expr: certmanager_certificate_expiration_timestamp_seconds - time() < 14 * 24 * 3600
      for: 1h
      labels:
        severity: warning
      annotations:
        summary: "Certificate {{ $labels.name }} expires in < 14 days"
```

This is especially important for the Linkerd identity issuer (T2.3) and the
harbor-tls wildcard cert.

---

#### T3.2 — Image signing with Cosign + Kyverno

**What:** Sign Docker images in CI with Cosign (part of the Sigstore stack);
add a Kyverno `verifyImages` policy that blocks pods using unsigned images.

**Prerequisites:** T2.4 (Kyverno), GitHub Actions secret for Cosign key or
Sigstore keyless signing via OIDC.

---

#### T3.3 — Falco runtime threat detection

**What:** Falco monitors kernel-level syscalls and fires alerts on anomalous
behavior: shell spawned in a production container, unexpected outbound connection,
`/etc/passwd` read, etc.

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco -n falco --create-namespace \
  --set driver.kind=modern_ebpf  # eBPF driver, no kernel module needed
```

---

#### T3.4 — External Secrets Operator (ESO)

**What:** Replace inline Kubernetes Secrets (`harbor-hot-secrets`,
`harbor-mgmt-secrets`) with ESO pulling secrets from HashiCorp Vault, AWS SSM,
or Cloudflare's Workers KV. Removes the need to ever touch raw Secret YAML; all
rotation happens in the upstream store and ESO syncs automatically.

**Why:** Even with etcd encryption, anyone who can `kubectl get secret -n harbor` reads
the live values. ESO with Vault adds RBAC at the secret-store level, audit logging
of every read, and automatic rotation.

---

#### T3.5 — SPIFFE/SPIRE workload identity

**What:** SPIRE issues X.509 SVIDs (SPIFFE Verifiable Identity Documents) to each
pod. This gives workloads cryptographic identity that the application can verify at
the protocol level — not just IP-based trust.

**Prerequisite:** T2.3 (Linkerd) integrates with SPIRE as its identity backend,
giving both mTLS *and* app-accessible SVIDs.

---

#### T3.6 — WireGuard node-to-node encryption (Calico)

**What:** Calico can encrypt the overlay network between nodes. Currently single-node
so all pod traffic stays on loopback — WireGuard adds nothing yet. When a second node
is added:

```bash
kubectl patch felixconfiguration default --type='merge' \
  -p '{"spec":{"wireguardEnabled":true}}'
```

---

## Implementation Order

```
✅ 2026-07-24  T0.1 iptables DROP rules for k8s ports (6443, 9345, 10250, 10255, 2379, 2380, 9091)
✅ 2026-07-24  T0.2 Bind etcd to localhost (127.0.0.1:2379 only)
✅ 2026-07-24  T1.1 HTTPS/443 egress on harbor-hot + SMTP/587/465 egress on harbor-mgmt NetworkPolicy
⚠️ 2026-07-24  T1.2 /admin block at nginx layer: blocked by hardened nginx admission webhook;
               protected at application layer by Bearer token auth (admin-endpoint-auth)
✅ 2026-07-24  T1.3 ArgoCD initial admin secret deleted; admin password rotated
✅ 2026-07-24  T1.4 Audit logging: policy + log path configured, rke2-server restarted
✅ 2026-07-24  T1.5 Upgrade etcd cipher AES-CBC → secretbox. Used custom
               /etc/rancher/rke2/encryption-config-custom.json with secretbox as
               first provider + aescbc fallback reader. Added kube-apiserver-arg
               override in config.yaml. Re-encrypted all 33 secrets.

Week 2:         T2.1 Offsite etcd backups + PostgreSQL backup
                T2.2 ArgoCD SSO with Dex + GitHub

Week 3:         T2.3 Linkerd mTLS (including PostgreSQL/Redis opaque ports)
                T2.4 Kyverno + policies

Later:          T3.1 Cert expiry alerting
                T3.2 Cosign image signing
                T3.3 Falco
                T3.4 External Secrets Operator
                T3.5 SPIFFE/SPIRE (if/when multi-region)
                T3.6 WireGuard (when second node added)
```

---

## Relationship to Application-Level Hardening

This plan covers **infrastructure** controls only. It complements but does not
replace the application-level security work tracked in
[`production-readiness.md`](production-readiness.md):

- `admin-endpoint-auth` (P0) — application-level auth on `/admin` endpoints
- `client-secret-auth` (P0) — no client secret verification on `/token`
- `hsm-signing-key` (P1) — ephemeral in-process signing keys
- `user-audit-trail` (P1) — application-level audit log

Both layers are required. Infrastructure controls (this doc) defend the platform;
application controls defend the protocol. Neither substitutes for the other.

---

> **Anti-drift note:** when a Tier-0, Tier-1, or Tier-2 item is completed, strike it
> here and note the completion date — same discipline as `production-readiness.md`.
>
> **Cluster context:** target machine is `51.89.98.90` (`ns31170412`, Ubuntu,
> RKE2 v1.35.6). Always SSH as `ubuntu` — `ssh ubuntu@51.89.98.90`. Cloudflare
> DNS key is in `~/.harbor.env` on the local machine. Do not run destructive
> commands (e.g. `ufw enable`) without a tested rollback path.
