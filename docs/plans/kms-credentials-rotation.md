# Plan — KMS Credential Rotation via External Secrets Operator (`kms-credentials-rotation`)

> **Status:** draft · **Priority:** HIGH (KMS is live in production with static
> credentials) · **Target:** `harbor` namespace on `51.89.98.90` (RKE2 on OVH bare
> metal — **not** EKS, **not** EC2) · **Parent:** [`infra-hardening.md`](infra-hardening.md)
> (T3.4 ESO, pulled forward) + `kms-provider-integration` (#79, shipped)

## 1. Problem statement

Harbor's KMS-backed signing keys landed (`kms-provider-integration`, PR #79): the KEK
now lives in AWS KMS. But the pod authenticates to AWS with **static credentials** —
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars sourced from the
`aws-kms-credentials` Kubernetes Secret. That means:

- A long-lived IAM user access key that **never rotates**; anyone who ever reads the
  Secret (or the etcd backup, or a pod env dump) holds durable AWS access to the KMS key
  that protects every user's DEK.
- Rotation today is fully manual: create key → edit Secret → restart pods → deactivate
  old key. Nobody does this, so the key ages indefinitely.
- The credential is the crypto root of trust for envelope encryption — it deserves the
  strongest handling in the platform and currently has the weakest.

### Why the obvious fixes don't apply here

| Option | Verdict |
|---|---|
| **IRSA** (`eks.amazonaws.com/role-arn` on the `harbor-hot` ServiceAccount) | ❌ EKS-only — requires the EKS OIDC provider + AWS-managed pod identity webhook. This is RKE2. |
| **EC2 instance profile** (node IAM role) | ❌ The node is an OVH bare-metal server (`51.89.98.90`), not EC2 — no instance metadata service, no instance role. |
| **amazon-eks-pod-identity-webhook / Kiam self-hosted** | ⚠️ Technically possible on any cluster (project the SA token, register the cluster's OIDC issuer JWKS with AWS IAM as an OIDC provider) but requires publicly serving the API server's OIDC discovery docs and adds a webhook to the pod-creation critical path — heavy for a single-node cluster, and Kiam is deprecated. Documented as rejected. |
| **External Secrets Operator + AWS Secrets Manager/SSM** | ✅ **Chosen.** Right pattern for non-EKS clusters: the AWS credential moves out of git and etcd-as-source-of-truth; ESO syncs it, rotation upstream propagates automatically, every read is CloudTrail-audited. |
| **Sealed Secrets** | ⚠️ Solves *git* storage only — the credential is still static and unrotated at runtime. Noted as complementary (for ESO's own bootstrap credential), not the solution. |

## 2. Approach

### 2.1 Architecture

```
AWS Secrets Manager                    RKE2 cluster
  harbor/prod/kms-credentials  ──►  ESO (external-secrets ns)
  (access key for harbor-kms         │  SecretStore (harbor ns, static auth via
   IAM user; rotated on a            │  eso-aws-bootstrap Secret — the ONLY
   schedule)                         │  hand-provisioned credential left)
                                     ▼
                              ExternalSecret ──► Secret aws-kms-credentials
                                     │             (refreshInterval: 1h)
                                     ▼
                              harbor-hot Deployment (unchanged envFrom/secretKeyRef)
```

Two-tier credential model (explicit, documented trade-off):
- **Bootstrap credential** (`eso-aws-bootstrap`): one minimal IAM user whose *only*
  permission is `secretsmanager:GetSecretValue` on `harbor/prod/*`. Provisioned once by
  the operator, out-of-band (never committed; optionally Sealed-Secrets-encrypted for
  git as a fast-follow).
- **Workload credential** (`harbor-kms` IAM user): permissions limited to
  `kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey`, `kms:DescribeKey` on the single
  Harbor KEK ARN. **This one now rotates**: rotate in IAM → update the Secrets Manager
  secret → ESO propagates within `refreshInterval` → pods pick it up (see 2.3).

We do not eliminate static credentials entirely (impossible without an OIDC federation
path on non-EKS); we **reduce to one narrowly-scoped, audited bootstrap credential** and
make the KMS credential rotatable in minutes with no cluster access.

### 2.2 Deliverables (in-repo)

```
deploy/eso/
  values-eso.yaml                 # external-secrets Helm values (single replica, pinned)
  secretstore-aws.yaml            # SecretStore (harbor ns) → AWS Secrets Manager,
                                  #   auth via eso-aws-bootstrap secretRef
  externalsecret-kms.yaml         # ExternalSecret → target Secret aws-kms-credentials,
                                  #   refreshInterval 1h, creationPolicy Owner
  networkpolicy-eso.yaml          # ESO egress: DNS + 443 only
  kustomization.yaml
  README.md                       # IAM setup, bootstrap provisioning, rotation runbook
```

Namespaced `SecretStore` (not `ClusterSecretStore`) — blast-radius: only the `harbor`
namespace can reference it. `creationPolicy: Owner` + `deletionPolicy: Retain` so a
broken ESO never deletes the live credential out from under the hot path.

### 2.3 Rotation propagation to pods

Env vars are read at process start; a Secret update alone doesn't reach running pods.
Two mechanisms, both shipped:
1. **Reloader annotation** (`reloader.stakater.com/auto: "true"`) on `deployment-hot`
   if Stakater Reloader is installed — automatic rolling restart on Secret change; or
   the documented manual `kubectl rollout restart deployment/harbor-hot -n harbor`.
2. **Overlap window runbook**: AWS allows two active access keys per IAM user — create
   key 2 → update Secrets Manager → wait > refreshInterval + rollout → verify KMS calls
   on key 2 (CloudTrail) → deactivate key 1. Zero-downtime by construction.

Go-code note: no Go changes required (the AWS SDK env-var chain is untouched). If a
cheap win is available, add a startup log line in `cmd/harbor-hot` masking-printing the
access-key ID suffix to make "which key am I on" observable — optional.

### 2.4 Key decisions

1. **ESO over self-hosted IRSA-alike** — smallest operational surface for a single-node
   cluster; no public OIDC discovery requirement; deprecation-proof.
2. **AWS Secrets Manager over SSM Parameter Store** — native rotation hooks and
   CloudTrail granularity; SSM works too and the SecretStore is one field away if cost
   matters (documented).
3. **Two-tier credentials** — bootstrap cred can't touch KMS; workload cred can't read
   Secrets Manager. Compromise of either alone is contained.
4. **`refreshInterval: 1h`** — rotation propagates within an hour without hammering the
   Secrets Manager API (cost + rate limits).
5. **Retain-on-delete** — availability of the signing path beats cleanup hygiene.

## 3. Implementation steps

1. `deploy/eso/values-eso.yaml`: pinned chart, single replica, resource limits,
   `installCRDs: true`.
2. `secretstore-aws.yaml` + `externalsecret-kms.yaml` + NetworkPolicy + kustomization.
3. README runbook: IAM policy JSON for both principals, Secrets Manager secret layout,
   bootstrap provisioning command, rotation drill (2.3), break-glass (re-create
   `aws-kms-credentials` by hand if ESO is down — `deletionPolicy: Retain` means the
   last-synced Secret keeps working meanwhile).
4. Remove any committed/templated static `aws-kms-credentials` material from
   `deploy/helm`/`deploy/k8s` secret templates; the Secret is now ESO-owned (chart gains
   a `kmsCredentials.managedByESO` values flag to skip rendering it).
5. Wire into ArgoCD app-of-apps (ESO install wave before ExternalSecret CRs).
6. Update `infra-hardening.md` T3.4 row → pulled forward/complete; cross-link from
   `kms-provider-integration` doc.

## 4. Validation

- `kubectl apply --dry-run=client -k deploy/eso/` clean (CRD schemas via kubeconform
  with ESO schemas, or `--validate=false` fallback documented); `helm lint deploy/helm`
  green with the new values flag in both states.
- On-cluster: `kubectl get externalsecret -n harbor` shows `SecretSynced/Ready`;
  `aws-kms-credentials` Secret exists with expected keys and ESO ownerReference.
- End-to-end: harbor-hot restart → KMS decrypt of the KEK succeeds (existing KMS smoke/
  health check passes); CloudTrail shows calls from the workload key.
- **Rotation drill executed once** per §2.3 before marking complete: old key
  deactivated, zero failed KMS calls during the window.
- Negative test: scale ESO to 0 → existing Secret persists (Retain), harbor unaffected.
- Repo checks: `go build ./... && go vet ./... && go test ./... && make agent-check` green.
