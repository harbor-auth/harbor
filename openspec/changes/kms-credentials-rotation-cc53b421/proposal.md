# Proposal: KMS credentials rotation via External Secrets Operator

## Problem

The KMS-backed signing key feature (#79) ships `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY` as a **static** Kubernetes Secret (`harbor-hot-secrets`).
Static credentials cannot be rotated without a manual `kubectl` secret-edit and a
pod restart — a high-friction, error-prone operation that leaves a long credential
lifetime as the operational default, widening the blast radius of any leakage.

The cluster is **OVH/RKE2** (not EKS), so there is no pod-identity webhook or
IRSA equivalent; the credential must be presented as an env var. This means
rotation requires a new mechanism, not just an IAM change.

## Proposed Solution

Deploy the **External Secrets Operator (ESO)** and pull KMS credentials from
**AWS SSM Parameter Store**, giving automatic rotation without code changes:

1. **ESO Helm install** (`deploy/eso/values-eso.yaml`) — single replica, resource
   caps tuned for the single-node cluster.
2. **ClusterSecretStore** (`deploy/eso/cluster-secret-store.yaml`) — points at
   AWS SSM Parameter Store; authenticates with a bootstrap IAM user whose
   credentials are loaded from a Sealed Secret (`eso-ssm-credentials`). The
   bootstrap IAM user has `SSM:GetParameter` on `/harbor/*` only and **no KMS
   rights** (least privilege; KMS rights stay on the existing KMS role).
3. **ExternalSecret** (`deploy/eso/external-secret-kms.yaml`) — maps SSM paths
   `/harbor/kms/aws-access-key-id` and `/harbor/kms/aws-secret-access-key` into
   the `harbor-kms-credentials` Secret in the `harbor` namespace, with a 1-hour
   refresh interval. Ops rotates in SSM; ESO syncs in ≤ 1 h with no restart.
4. **harbor-hot Deployment** updated to consume `harbor-kms-credentials` via a
   second `envFrom.secretRef` (Helm + raw k8s manifests), keeping the deployment
   schema backward-compatible.

## Non-Goals

- IRSA / pod identity (unavailable on OVH/RKE2).
- Rotation of the SSM bootstrap IAM user's own credentials (separate ops concern).
- East-west mTLS (T2.3 Linkerd).
- Any change to Go application code — ESO delivers the same env vars the process
  already reads; zero application changes.

## Success Criteria

- [ ] ESO Helm values (`deploy/eso/values-eso.yaml`) size the operator for a
  single-node cluster.
- [ ] `ClusterSecretStore` references the bootstrap Sealed Secret for IAM creds;
  the IAM user has `SSM:GetParameter` on `/harbor/*` only.
- [ ] `ExternalSecret` maps both SSM paths into `harbor-kms-credentials` with a
  1h refresh; `harbor-hot` receives `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
  from that Secret.
- [ ] `kubectl apply --dry-run=client -k deploy/eso/` succeeds.
- [ ] `README.md` documents bootstrap, rotation, and rollback procedures.
- [ ] `go build ./... && go vet ./... && go test ./... && make agent-check` green.
