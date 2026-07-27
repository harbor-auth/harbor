# Tasks: Offsite etcd + PostgreSQL Backup

## Prerequisites

- [ ] **No DB migration** — this feature adds only Kubernetes manifests, config
  snippets, and documentation. No Go source files are modified and no SQL migration
  is required. This change reserves no migration prefix.
- [ ] **No Go code changes** — `go build ./... && go vet ./... && go test ./...`
  must remain green throughout; these commands are run as a regression check only.
- [ ] Depends on the existing `harbor-postgresql` Service and Secret (deployed by
  the Harbor Helm chart) for the pg_dump CronJob's hostname and password reference.
- [ ] Cloudflare R2 bucket (`harbor-backups`) and scoped credentials
  (`backup-credentials`) must be provisioned by the operator before deploying;
  credential values are supplied at deploy time via `~/.harbor.env` and patched
  into the Secret — they are never committed.

## Implementation

- [ ] `deploy/backup/namespace.yaml` — `harbor-backup` namespace with
  `pod-security.kubernetes.io/enforce: privileged` label (required for hostPath
  mount in the etcd sync CronJob).
- [ ] `deploy/backup/serviceaccount.yaml` — `harbor-backup` ServiceAccount in the
  `harbor-backup` namespace.
- [ ] `deploy/backup/networkpolicy-backup.yaml` — egress NetworkPolicy permitting
  only DNS (53/UDP+TCP) and HTTPS (443/TCP); deny all ingress.
- [ ] `deploy/backup/secret-backup-credentials.yaml` — template Secret with
  placeholder values (`REPLACE_ME`) for R2/S3 access key, secret key, and endpoint.
  Must include a prominent comment: **DO NOT COMMIT REAL VALUES**.
- [ ] `deploy/backup/cronjob-etcd-sync.yaml` — CronJob `harbor-etcd-sync`,
  schedule `0 */6 * * *`, rclone image, `hostPath` read-only mount of
  `/var/lib/rancher/rke2/server/db/snapshots/`, rclone config from
  `backup-credentials` Secret volume, `restartPolicy: OnFailure`,
  `backoffLimit: 2`, `activeDeadlineSeconds: 3600`,
  `concurrencyPolicy: Forbid`.
- [ ] `deploy/backup/cronjob-pgdump.yaml` — CronJob `harbor-pgdump`,
  schedule `0 3 * * *`, rclone + postgresql-client image,
  `pg_dump -Fc | rclone rcat` streaming to bucket, `PGHOST=harbor-postgresql`,
  `PGPASSWORD` from `harbor-postgresql` Secret via `secretKeyRef`,
  `restartPolicy: OnFailure`, `backoffLimit: 2`,
  `activeDeadlineSeconds: 1800`, `concurrencyPolicy: Forbid`.
- [ ] `deploy/backup/rke2-etcd-s3-config-snippet.yaml` — a YAML comment file (not
  a Kubernetes manifest) documenting the host-level RKE2 `etcd-s3` config block
  to be applied by the operator to `/etc/rancher/rke2/config.yaml`. Include the
  `etcd-snapshot-schedule-cron`, `etcd-snapshot-retention`, `etcd-s3`,
  `etcd-s3-endpoint`, `etcd-s3-bucket`, `etcd-s3-region`, and `etcd-s3-folder`
  fields with placeholder values.
- [ ] `deploy/backup/kustomization.yaml` — wire all resources: namespace,
  serviceaccount, networkpolicy, secret template, both CronJobs. The RKE2 snippet
  file is documentation only and MUST NOT be included in the kustomization
  resources list.
- [ ] `deploy/backup/README.md` — operator restore runbook and retention policy
  (see task `ftask_eca83a29`). This file is part of the same deliverable but
  authored as a separate task for clarity.

## Tests

- [ ] **kubectl dry-run:** `kubectl apply --dry-run=client -k deploy/backup/`
  exits 0 with no validation errors. Run against a live cluster or a
  `kubeconform`-based CI check.
- [ ] **YAML lint:** all manifests pass `kubeconform` (or `kubeval`) schema
  validation; no unknown fields.
- [ ] **Secret hygiene check:** `grep -r 'REPLACE_ME' deploy/backup/` finds only
  the template placeholder; `grep -rE '[A-Za-z0-9+/]{40,}' deploy/backup/secret*`
  finds no real credential strings.
- [ ] **Manual trigger (post-deploy):**
  - `kubectl create job --from=cronjob/harbor-pgdump pgdump-smoke-$(date +%s) -n harbor-backup`
    → dump object appears in bucket; `pg_restore --list <downloaded-dump>` succeeds.
  - `kubectl create job --from=cronjob/harbor-etcd-sync etcd-smoke-$(date +%s) -n harbor-backup`
    → snapshot objects appear in bucket.
- [ ] **Restore drill:** execute the etcd and PostgreSQL restore runbooks against a
  scratch environment before marking the feature complete. An unverified restore
  runbook is not a backup.

## Validation

- [ ] `kubectl apply --dry-run=client -k deploy/backup/` exits 0.
- [ ] `go build ./... && go vet ./... && go test ./...` green (no Go changes;
  regression check only).
- [ ] `make agent-check` green.
- [ ] `openspec validate offsite-etcd-backup-7148cfc8 --strict`
