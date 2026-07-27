# Tasks: KMS credentials rotation via External Secrets Operator

## Prerequisites

- [ ] KMS-backed signing key feature (#79) is on `main` (provides the
  `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars that harbor-hot already
  reads). No other hard dependency — this change is pure infra/YAML with no Go
  changes and no migrations.
- [ ] Ops has created an IAM user with `ssm:GetParameter` on `/harbor/*` only
  (no KMS rights) and set the SSM parameters `/harbor/kms/aws-access-key-id` and
  `/harbor/kms/aws-secret-access-key`.
- [ ] Sealed Secrets controller is installed in the cluster (for the bootstrap
  `eso-ssm-credentials` Secret).

## Implementation

- [ ] `docs/plans/kms-credentials-rotation.md`: author the plan document (problem,
  solution, key decisions, bootstrap/rotation/rollback procedures). Add row to
  Plans table in `docs/README.md`.
- [ ] `deploy/eso/values-eso.yaml`: ESO Helm values — `replicaCount: 1`, tight
  CPU/memory requests+limits for a single-node cluster, certController and webhook
  disabled or minimally configured.
- [ ] `deploy/eso/cluster-secret-store.yaml`: `ClusterSecretStore` pointing at
  AWS SSM Parameter Store (`region: us-east-1` or configured region),
  authenticating with a Kubernetes Secret named `eso-ssm-credentials` in the
  `external-secrets` namespace. Include a comment that `eso-ssm-credentials` MUST
  be provisioned via Sealed Secret (not stored in plaintext).
- [ ] `deploy/eso/external-secret-kms.yaml`: `ExternalSecret` with
  `refreshInterval: 1h`, referencing the ClusterSecretStore, mapping
  `/harbor/kms/aws-access-key-id` → `AWS_ACCESS_KEY_ID` and
  `/harbor/kms/aws-secret-access-key` → `AWS_SECRET_ACCESS_KEY` into the
  `harbor-kms-credentials` Secret in the `harbor` namespace.
- [ ] `deploy/eso/kustomization.yaml`: kustomization grouping
  `cluster-secret-store.yaml` and `external-secret-kms.yaml`.
- [ ] `deploy/helm/templates/deployment-hot.yaml` + `deploy/helm/values.yaml`:
  add `hot.kmsSecret.existingSecret` value (default: `""`); when non-empty, emit
  a second `envFrom.secretRef` for `harbor-kms-credentials`.
- [ ] `deploy/k8s/deployment-hot.yaml`: mirror the second `envFrom.secretRef`
  for `harbor-kms-credentials` in the raw manifest.
- [ ] `README.md`: add an External Secrets Operator section documenting:
  (1) bootstrap procedure — `helm install external-secrets`, create
  `eso-ssm-credentials` Sealed Secret (kubeseal), `kubectl apply -k deploy/eso/`;
  (2) rotation procedure — update SSM parameters, ESO auto-syncs within 1h;
  (3) rollback — revert SSM values or manually patch `harbor-kms-credentials`.

## Tests / Validation

- [ ] `kubectl apply --dry-run=client -k deploy/eso/` passes (structural YAML
  validation against the CRD schemas present in the cluster).
- [ ] `go build ./... && go vet ./... && go test ./...` — no regressions (no Go
  code changed; this confirms no accidental Go file drift).
- [ ] `make agent-check` green.
- [ ] `openspec validate kms-credentials-rotation-cc53b421 --strict` passes.
- [ ] In the live cluster: ESO controller logs show `SecretSynced` for the
  ExternalSecret; `harbor-hot` restarts with new credentials and
  `curl https://auth.harborauth.com/jwks.json` returns signing keys.
