---
title: Offsite etcd + PostgreSQL backup
slug: offsite-etcd-backup
status: draft
openspec: openspec/changes/offsite-etcd-backup-7148cfc8/
---

# Plan: Offsite etcd + PostgreSQL backup (T2.1)

## Goal

Eliminate the single-point-of-failure for Harbor's control-plane and database by
shipping automated offsite backups for:

1. **RKE2 etcd snapshots** — synced to S3/Cloudflare R2 every 6 hours via rclone
2. **Harbor PostgreSQL database** — dumped and uploaded daily at 03:00 UTC

## Deliverables

- `deploy/backup/secret-backup.yaml` — Kubernetes Secret (placeholder credentials)
- `deploy/backup/cronjob-etcd.yaml` — etcd snapshot rclone CronJob (every 6 h)
- `deploy/backup/rke2-etcd-s3-snippet.yaml` — RKE2 native etcd-s3 config snippet
- `deploy/backup/cronjob-pgdump.yaml` — pg_dump CronJob (daily 03:00 UTC)
- `deploy/backup/kustomization.yaml` — kustomize entry point for the stack
- `deploy/backup/README.md` — restore runbook + retention policy (7 days)

## Key Decisions

- **rclone** for R2 compatibility (also supports S3); same image handles both providers
- **Credentials** in a dedicated `backup-credentials` Secret; never baked into images
- **Retention**: `rclone --max-age 168h` (7 days) enforced client-side at sync time
- **pg_dump** reads password from the existing `harbor-postgresql` Secret
- **etcd CronJob** pinned to control-plane node via `nodeAffinity`
- No new Go code — purely Kubernetes manifests

## Validation

```bash
kubectl apply --dry-run=client -k deploy/backup/
go build ./... && go vet ./... && go test ./...
make agent-check
```

## OpenSpec

Paired spec: `openspec/changes/offsite-etcd-backup-7148cfc8/`
