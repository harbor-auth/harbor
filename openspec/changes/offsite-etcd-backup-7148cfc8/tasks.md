# Tasks: Offsite etcd + PostgreSQL backup (T2.1)

## Prerequisites

- [ ] No DB migration — this feature adds only Kubernetes manifests.
- [ ] No Go code changes — the existing Go build/test suite must remain green.
- [ ] RKE2 cluster with etcd snapshots at `/var/lib/rancher/rke2/server/db/snapshots/`.
- [ ] S3-compatible bucket (AWS S3 or Cloudflare R2) pre-created by the operator.

## Implementation

- [ ] `openspec/changes/offsite-etcd-backup-7148cfc8/` — author all OpenSpec artifacts
  (proposal.md, design.md, specs/backup-requirements.md, tasks.md) and create
  `docs/plans/offsite-etcd-backup.md`.
- [ ] `deploy/backup/secret-backup.yaml` — create Kubernetes Secret manifest with
  placeholder rclone credentials (CHANGEME values; operator fills in real creds).
- [ ] `deploy/backup/cronjob-etcd.yaml` — create CronJob for etcd snapshot rclone
  sync every 6 hours with hostPath volume, nodeAffinity for control-plane, and
  `rclone sync --max-age 168h`.
- [ ] `deploy/backup/rke2-etcd-s3-snippet.yaml` — informational RKE2 config snippet
  for native etcd-s3 upload (alternative to the CronJob approach).
- [ ] `deploy/backup/cronjob-pgdump.yaml` — create CronJob for daily pg_dump at
  03:00 UTC using postgres:16 image, sourcing password from harbor-postgresql
  Secret, uploading via `rclone copyto` and pruning with `rclone delete --min-age 168h`.
- [ ] `deploy/backup/kustomization.yaml` — wire Secret, both CronJobs into a
  single kustomize entry point.
- [ ] `deploy/backup/README.md` — restore runbook covering etcd restore
  (rclone copy + rke2 etcd-snapshot restore) and PostgreSQL restore
  (rclone copy + pg_restore), credential setup, and 7-day retention policy.

## Validation

- [ ] `kubectl apply --dry-run=client -k deploy/backup/` exits 0.
- [ ] `go build ./... && go vet ./... && go test ./...` all pass (no regressions).
- [ ] `make agent-check` is green.
- [ ] `openspec validate offsite-etcd-backup-7148cfc8 --strict` passes.
