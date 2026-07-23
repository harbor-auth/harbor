# Harbor — Infrastructure Hardening Plan

> **Authored:** 2026-07-23 · **Revised:** 2026-07-23 (post Fable analysis + live cluster
> verification) · **Target cluster:** `51.89.98.90` (`ns31170412`) · RKE2 v1.35.6
> · single-node · Calico CNI · ArgoCD GitOps
>
> **Bottom line:** the cluster has solid L3/L4 micro-segmentation and enforces Pod
> Security Admission at the `restricted` profile, but has **several critical
> host-level exposures** (etcd on public IP, no host firewall, kubelet and kube-apiserver
> publicly reachable) alongside medium gaps (AES-CBC encryption cipher, no audit
> logging, no east-west mTLS, no ArgoCD SSO). Fix the host-level items first — they
> are reachable from the internet today.

---

## Current Security Posture

### ✅ What is already in place

| Control | Detail |
|---|---|
| **etcd encryption at rest** | Already enabled by RKE2 default — `Encryption Status: Enabled`, active key `AES-CBC aescbckey`. Secrets are not stored in plaintext. However, see gap below: AES-CBC is a weaker cipher than the upstream-recommended `secretbox`. |
| **Egress NetworkPolicies** | harbor-hot and harbor-mgmt both have egress rules applied in the `harbor` namespace, locking egress to DNS (53), Redis (6379), and PostgreSQL (5432) only. Not unrestricted. See gap below: **HTTPS egress (443) is missing** from harbor-hot. |
| **Calico NetworkPolicies (ingress)** | Every workload has an explicit L3/L4 ingress policy: `harbor-hot` (from kube-system ingress controller only), `harbor-mgmt` (same-namespace pods only), `harbor-postgresql`, `harbor-redis`, and all ArgoCD components. |
| **Pod Security Admission — `restricted`** | The `harbor` namespace enforces `pod-security.kubernetes.io/enforce: restricted` (latest). Prevents privileged containers, host-network/PID access, requires explicit securityContexts. |
| **TLS at ingress** | cert-manager + Cloudflare DNS-01 wildcard certificate on `auth.harborauth.com`. Traffic from the internet is TLS-terminated at the nginx ingress. |
| **Calico CNI** | RKE2 ships with Calico, enforcing NetworkPolicy at kernel level via iptables/eBPF. `clusternetworkpolicies.policy.networking.k8s.io` CRD is present. |
| **ArgoCD GitOps** | All cluster state is managed declaratively; ad-hoc `kubectl apply` changes are detected and reconciled away. |
| **etcd snapshots** | RKE2 takes daily snapshots automatically (stored in `/var/lib/rancher/rke2/server/db/snapshots/`). |

### 🔴 Critical Gaps (reachable from internet today)

| Gap | Risk |
|---|---|
| **etcd listening on public IP** | `51.89.98.90:2379` is open to the internet. etcd has no authentication in its default single-node RKE2 setup. Anyone who can reach this port can read all cluster state including Secrets. |
| **No host-level firewall (UFW inactive)** | `ufw status: inactive`. All ports reachable from the internet: kube-apiserver `:6443`, RKE2 join port `:9345`, kubelet API `:10250`, Calico metrics `:9091`. An attacker can reach the Kubernetes API server directly from the internet with no rate limiting or IP allowlist. |
| **kube-apiserver (6443) exposed to internet** | Direct API server access from any IP. A stolen service account token, credential stuffing, or a vulnerability in the API server is directly exploitable. |
| **kubelet API (10250) exposed to internet** | The kubelet API allows exec/log access to pods if authenticated. A leaked token or kubelet vulnerability is directly exploitable. |

### 🟡 Significant Gaps

| Gap | Risk |
|---|---|
| **AES-CBC encryption cipher** | etcd secrets are encrypted but with AES-CBC — an older CBC-mode cipher with known vulnerabilities (padding oracle, IV reuse risk). Upstream Kubernetes recommends `secretbox` (XSalsa20+Poly1305) as the primary cipher. |
| **Missing HTTPS egress on harbor-hot** | The harbor-hot egress NetworkPolicy has no port-443 rule. Any outbound HTTPS call from harbor-hot (e.g. Cloudflare KMS API, JWKS external fetch if configured) will be silently blocked. |
| **No Kubernetes API audit logging** | Zero tamper-evident record of API server actions — cannot detect credential theft, privilege escalation, or Secret exfiltration after the fact. |
| **No admin endpoint protection at ingress** | `harbor-hot` exposes `/admin/keys/rotate` and `/admin/revoke-jwt`. These are currently reachable from the internet via the nginx ingress because there is no path-based blocking at the ingress layer. (App-level auth is tracked in `production-readiness.md`; this covers the infra layer.) |
| **ArgoCD using initial admin password, no SSO** | ArgoCD's initial auto-generated admin password is still active (`argocd-initial-admin-secret`). No SSO is configured. ArgoCD has full cluster deploy access. |
| **etcd snapshots are local-only** | Daily snapshots exist but are only on the same node. A disk failure or node compromise destroys both the live data and the backup. |
| **No east-west mTLS** | Pod-to-pod traffic (hot↔postgres, mgmt↔redis) is unencrypted plaintext inside the node. Node-level access can expose DB queries and session data. |
| **No policy-as-code** | No Kyverno or OPA Gatekeeper. No enforcement of image signing, image digest pinning, resource limits, or label requirements. |
| **No runtime threat detection** | No Falco or equivalent — no alerting on anomalous syscalls (e.g. shell spawned inside `harbor-hot`). |

---

## Hardening Roadmap

### Tier 0 — Critical host exposure (do immediately, < 1 hour total)

These items are reachable from the internet **right now**. Do not proceed to other tiers
before completing these.

---

#### T0.1 — Enable UFW and block dangerous ports

**What:** Enable the host firewall and restrict internet-reachable ports to only
what is required (HTTP, HTTPS, SSH). All Kubernetes internal ports must be
blocked from external access.

**How:**
```bash
ssh ubuntu@51.89.98.90

# Allow only the ports that must be internet-facing
sudo ufw allow 22/tcp    # SSH (do this FIRST or you lock yourself out)
sudo ufw allow 80/tcp    # HTTP (nginx ingress, for redirect to HTTPS)
sudo ufw allow 443/tcp   # HTTPS (nginx ingress)

# Block Kubernetes internals from internet
# (kube-apiserver, RKE2 join, kubelet, Calico metrics)
# These stay accessible via loopback/internal — only internet-originating
# packets are blocked by UFW's default-deny-incoming policy.

# Enable UFW with default deny-incoming
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable

# Verify
sudo ufw status verbose
```

> ⚠️ **Warning:** Do not add a rule for 6443 unless you need kubectl access from
> outside. If you do, restrict it to your IP only:
> `sudo ufw allow from <YOUR_IP> to any port 6443`

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

**How:** Add to the Ingress annotations in `deploy/helm/templates/ingress.yaml`:
```yaml
annotations:
  nginx.ingress.kubernetes.io/server-snippet: |
    location ~* ^/admin/ {
      deny all;
      return 403;
    }
```

Or use a separate Ingress resource with `nginx.ingress.kubernetes.io/deny-admission`
if your nginx version supports it. Test with:
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

**How:** RKE2 does not yet expose a direct `config.yaml` option to change the
cipher. The path is:

1. Generate a new `secretbox` provider configuration (see Kubernetes
   [Encrypting Secret Data at Rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)).
2. Patch the existing encryption config at
   `/var/lib/rancher/rke2/server/cred/encryption-config.json` to add `secretbox`
   as the first provider and `aescbc` as fallback (for reading existing secrets).
3. Restart rke2-server.
4. Force re-encryption: `sudo rke2 secrets-encrypt reencrypt --force`
5. Verify: `sudo rke2 secrets-encrypt status`
6. Once all secrets are re-encrypted, remove the `aescbc` fallback provider.

> **Important:** `systemctl restart rke2-server` alone does NOT re-encrypt existing
> secrets. You must explicitly run `rke2 secrets-encrypt reencrypt` to migrate all
> existing Secrets from the old cipher to the new one.

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
Week 1, Day 1:  T0.1 Enable UFW (30 min) — blocks internet access to 6443, 10250, 9345
                T0.2 Bind etcd to localhost (15 min)

Week 1:         T1.1 Add HTTPS egress to harbor-hot NetworkPolicy (10 min)
                T1.2 Block /admin/* at nginx ingress (15 min)
                T1.3 Rotate ArgoCD admin credentials (10 min)
                T1.4 Enable audit logging (20 min)
                T1.5 Upgrade encryption cipher to secretbox (30 min)

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
