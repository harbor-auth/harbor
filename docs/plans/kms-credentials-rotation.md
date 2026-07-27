---
title: KMS Credentials Rotation via External Secrets Operator
status: in-progress
design_refs: [§7.3, §4.4, §A.4]
targets: [deploy/eso/, docs/plans/]
promoted_to: null
openspec: null
created: 2026-07-27
---

# KMS Credentials Rotation via External Secrets Operator (plan)

> **Parent:** [`infra-hardening.md`](infra-hardening.md) (T3.4 ESO, pulled forward to
> T2 priority) · **Depends on:** `kms-provider-integration` (#79, shipped) ·
> **Feature branch:** `weft/kms-credentials-rotation-cc53b421`

## Problem

Harbor's KMS-backed signing keys landed in `kms-provider-integration` (PR #79): the
Key Encryption Key (KEK) now lives in AWS KMS and signs tokens via the
`kmsKeyProvider`. But the pod authenticates to AWS with **static credentials** —
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars sourced from a hard-provisioned
`harbor-kms-credentials` Kubernetes Secret. That means:

- A long-lived IAM user access key that **never rotates**; anyone who reads the Secret
  (or an etcd backup, or a pod env dump) holds durable AWS KMS access — the root of
  trust for every user's Data Encryption Key.
- Rotation today is fully manual: generate key → update Secret → restart pods →
  deactivate old key. In practice this never happens.
- The credential is the crypto root of trust for envelope encryption (§4.4) and token
  signing (§7.3) — it deserves the strongest handling on the platform and currently
  has the weakest.

### Why the obvious fixes don't apply here

| Option | Verdict |
|---|---|
| **IRSA** (`eks.amazonaws.com/role-arn` on the `harbor-hot` ServiceAccount) | ❌ EKS-only — requires the EKS OIDC provider and AWS-managed pod identity webhook. This cluster is RKE2 on OVH bare metal. |
| **EC2 instance profile** (node IAM role) | ❌ The node is an OVH bare-metal server (`51.89.98.90`), not EC2 — no instance metadata service, no instance role. |
| **Self-hosted OIDC federation / Kiam** | ⚠️ Technically possible (project SA token, register cluster OIDC issuer JWKS with AWS IAM as an OIDC provider) but requires publicly serving API server OIDC discovery docs, adds a pod-creation webhook to the critical path, and Kiam is deprecated. Rejected. |
| **External Secrets Operator + AWS SSM Parameter Store** | ✅ **Chosen.** Right pattern for non-EKS clusters: the AWS credential moves out of etcd-as-source-of-truth; ESO syncs it on a schedule, rotation upstream propagates automatically, every read is CloudTrail-audited. |
| **Sealed Secrets alone** | ⚠️ Solves *git* storage only — the credential is still static and unrotated at runtime. Used as the ESO bootstrap mechanism (see §2 below), not the rotation solution. |

## Proposed approach

### Architecture

```
AWS SSM Parameter Store            RKE2 cluster (harbor ns)
  /harbor/kms/aws-access-key-id ──► ESO controller (external-secrets ns)
  /harbor/kms/aws-secret-access-key  │  ClusterSecretStore
  (rotated by ops on a schedule)     │    auth: eso-aws-bootstrap Secret
                                     │    (Sealed Secret bootstrap — the ONLY
                                     │    hand-provisioned credential left)
                                     ▼
                              ExternalSecret ──► harbor-kms-credentials Secret
                                     │            (refreshInterval: 1h)
                                     ▼
                              harbor-hot Deployment (envFrom / secretKeyRef — unchanged)
```

**Two-tier credential model** (explicit, audited trade-off):

- **Bootstrap credential** (`eso-aws-bootstrap` Secret, provisioned once via Sealed
  Secret): one minimal IAM user whose *only* permission is
  `ssm:GetParameter` on `arn:aws:ssm:*:*:parameter/harbor/*`. It cannot touch KMS.
  Optionally Sealed-Secrets-encrypted for git storage.
- **Workload credential** (in SSM at `/harbor/kms/aws-access-key-id` and
  `/harbor/kms/aws-secret-access-key`): the `harbor-kms` IAM user with permissions
  limited to `kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey`, `kms:DescribeKey`
  on the single Harbor KEK ARN. **This is the credential that now rotates**: ops
  rotate it in IAM → update SSM → ESO propagates within `refreshInterval` → pods
  pick it up on next rollout.

We do not eliminate static credentials entirely (impossible without an OIDC federation
path on non-EKS); we **reduce to one narrowly-scoped, audited bootstrap credential**
and make the KMS workload credential rotatable in minutes with no cluster access
required.

### Key decisions

1. **ESO over self-hosted IRSA-alike** — smallest operational surface for a
   single-node cluster; no public OIDC discovery requirement; deprecation-proof.
2. **SSM Parameter Store over Secrets Manager** — simpler IAM policy, lower cost
   for low-volume reads; same CloudTrail auditability. Secrets Manager rotation hooks
   are not needed since ESO drives the propagation.
3. **ClusterSecretStore (not namespaced SecretStore)** — allows the ESO controller
   in `external-secrets` ns to serve other namespaces in future without re-bootstrapping
   credentials. The ExternalSecret is still namespaced to `harbor`.
4. **`refreshInterval: 1h`** — rotation propagates within an hour without hammering
   SSM (cost + rate limits).
5. **`creationPolicy: Owner` + `deletionPolicy: Retain`** — availability of the
   signing path beats cleanup hygiene. A broken ESO never deletes the live credential.

### Rotation propagation to pods

Env vars are read at process start; a Secret update alone does not reach running pods.
Two mechanisms:

1. **Reloader annotation** (`reloader.stakater.com/auto: "true"`) on `harbor-hot`
   Deployment — automatic rolling restart on Secret change if Stakater Reloader is
   installed. Documented as preferred path.
2. **Manual runbook**: `kubectl rollout restart deployment/harbor-hot -n harbor`
   after ESO syncs.

**Zero-downtime rotation drill** (overlap window): AWS allows two active access keys per
IAM user — create key 2 → update SSM → wait > refreshInterval + rollout time → verify
KMS calls on key 2 via CloudTrail → deactivate key 1.

### Deliverables

```
deploy/eso/
  values-eso.yaml            # ESO Helm values: single replica, resource caps, installCRDs: true
  cluster-secret-store.yaml  # ClusterSecretStore → AWS SSM Parameter Store,
                             #   auth via eso-aws-bootstrap secretRef (harbor ns)
  external-secret-kms.yaml   # ExternalSecret → harbor-kms-credentials Secret,
                             #   SSM paths /harbor/kms/aws-access-key-id +
                             #   /harbor/kms/aws-secret-access-key, refreshInterval 1h
  kustomization.yaml
README.md (bootstrap, rotation, rollback runbook)
```

No Go code changes required — the AWS SDK env-var credential chain is untouched.

## DESIGN alignment

Serves §7.3 (regional KMS holds KEKs; KMS IAM credential must be handled with the
same rigor as the key material itself) and §4.4 (envelope encryption DEK wrapping;
the KEK access credential is the root of trust for crypto-shred guarantees). Also
supports §A.4 (operational security posture).

Does **not** change `DESIGN.md` — this is a deployment infrastructure change that
makes the existing design more operationally sound without altering any protocol,
data model, or API surface.

Cross-references:
- `kms-provider-integration` (shipped, PR #79) — introduced the static credential this plan eliminates.
- `infra-hardening.md` (T3.4) — ESO is the T3.4 item, pulled forward to T2 priority because KMS is live in production.

## Target code paths

| Path | Change |
|---|---|
| `deploy/eso/values-eso.yaml` | New — ESO Helm values |
| `deploy/eso/cluster-secret-store.yaml` | New — ClusterSecretStore for AWS SSM |
| `deploy/eso/external-secret-kms.yaml` | New — ExternalSecret mapping SSM → `harbor-kms-credentials` |
| `deploy/eso/kustomization.yaml` | New — kustomize entrypoint for the ESO overlay |
| `deploy/helm/templates/deployment-hot.yaml` | Update — `harbor-kms-credentials` Secret reference (envFrom or secretKeyRef) |
| `deploy/k8s/deployment-hot.yaml` | Update — same credential reference in raw manifest |
| `README.md` | Update — ESO bootstrap, rotation, and rollback procedure |
| `docs/plans/infra-hardening.md` | Update — T3.4 row marked pulled forward / complete |

## Implementation checklist

- [ ] `deploy/eso/values-eso.yaml` — single replica, resource limits (`requests: cpu 50m, memory 64Mi`; `limits: cpu 200m, memory 128Mi`), `installCRDs: true`, pinned chart version.
- [ ] `deploy/eso/cluster-secret-store.yaml` — ClusterSecretStore with `provider.aws.service: ParameterStore`, `provider.aws.region: us-east-1`, `auth.secretRef` pointing to `eso-aws-bootstrap` in the `harbor` namespace.
- [ ] `deploy/eso/external-secret-kms.yaml` — ExternalSecret targeting `harbor-kms-credentials` Secret, mapping `/harbor/kms/aws-access-key-id` → `AWS_ACCESS_KEY_ID` and `/harbor/kms/aws-secret-access-key` → `AWS_SECRET_ACCESS_KEY`, `refreshInterval: 1h`, `creationPolicy: Owner`, `deletionPolicy: Retain`.
- [ ] `deploy/eso/kustomization.yaml` — lists all ESO manifests in apply order (ClusterSecretStore after ESO CRDs, ExternalSecret last).
- [ ] Wire `harbor-kms-credentials` into `deploy/helm/templates/deployment-hot.yaml` (envFrom or secretKeyRef).
- [ ] Wire `harbor-kms-credentials` into `deploy/k8s/deployment-hot.yaml`.
- [ ] `README.md` — bootstrap procedure (IAM policy JSON for both principals, Sealed Secret provisioning command), rotation runbook (§2 overlap-window drill), rollback (break-glass: re-create Secret by hand — `deletionPolicy: Retain` means ESO down does not kill the hot path).
- [ ] Update `infra-hardening.md` T3.4 row to "pulled forward / in-progress".
- [ ] Validation: `kubectl apply --dry-run=client -k deploy/eso/` clean; `go build ./... && go vet ./... && go test ./... && make agent-check` green.
- [ ] Negative test documented: scale ESO to 0 → existing Secret persists (Retain), harbor-hot unaffected.

## Risks & open questions

| Risk | Mitigation |
|---|---|
| **Bootstrap credential compromise** | Scoped to `ssm:GetParameter /harbor/*` only — cannot touch KMS, cannot read other SSM paths. Optionally store as a Sealed Secret in git so provisioning is auditable and repeatable. |
| **ESO outage / CRD missing** | `deletionPolicy: Retain` guarantees the last-synced Secret outlives ESO. Break-glass: re-create `harbor-kms-credentials` by hand, then restart ESO. |
| **SSM rate limits** | 1h refresh interval keeps API calls to ~24/day — well within free tier limits. ESO uses exponential backoff on error. |
| **Secret not propagated to running pods** | Env vars are immutable after pod start. Document the rollout-restart step; consider Stakater Reloader for zero-touch. |
| **Two active keys window during rotation** | AWS IAM allows max 2 access keys per user. The overlap window is bounded by `refreshInterval` + rollout time (~5 min) — well within the 2-key limit. |
| **ClusterSecretStore blast radius** | ClusterSecretStore is cluster-scoped, but ExternalSecrets that consume it are namespace-scoped. Only pods in namespaces with an ExternalSecret referencing this store can pull secrets — no implicit elevation. |

## Definition of done

- All files under `deploy/eso/` created and `kubectl apply --dry-run=client -k deploy/eso/` exits 0.
- `harbor-kms-credentials` Secret is ESO-owned (ownerReference present) and contains expected keys.
- `harbor-hot` Deployment references `harbor-kms-credentials` (not a hand-provisioned static Secret).
- On-cluster smoke test: `kubectl get externalsecret -n harbor` shows `SecretSynced/Ready`; CloudTrail shows KMS calls from the workload key after a rolling restart.
- Rotation drill executed once per the overlap-window runbook with zero failed KMS calls during the window.
- `go build ./... && go vet ./... && go test ./... && make agent-check` green.
- `docs/README.md` Plans table updated; `infra-hardening.md` T3.4 row updated.
