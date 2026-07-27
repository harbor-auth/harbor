# Proposal: Offsite etcd + PostgreSQL backup (T2.1 infra hardening)

## Problem

Harbor's RKE2 control plane and PostgreSQL database have no offsite backup today.
A node loss or accidental `kubectl delete` wipes cluster state and user data with
no recovery path. This violates basic infra hardening requirements for a
production identity provider.

Two failure modes are unmitigated:

1. **Control-plane loss** — RKE2 etcd snapshots live only on the node that
   produced them (`/var/lib/rancher/rke2/server/db/snapshots/`). Node failure =
   snapshot loss.
2. **Database loss** — The harbor PostgreSQL instance holds all users, grants,
   sessions, and audit events. No automated dump exists offsite.

## Proposed Solution

1. **etcd offsite sync** — A Kubernetes CronJob running every 6 hours uses
   `rclone` to copy RKE2 etcd snapshots from the host path into an S3-compatible
   bucket (AWS S3 or Cloudflare R2). RKE2's native `etcd-snapshot-schedule-cron`
   with `etcd-s3` flags is also documented as an alternative/complement.
2. **PostgreSQL daily dump** — A second CronJob runs `pg_dump` daily at 03:00
   UTC and uploads the compressed dump to the same bucket under `db-backups/`.
   Credentials are sourced from the existing `harbor-postgresql` Kubernetes
   Secret.
3. **Retention** — Both jobs enforce a 7-day (168 h) rolling retention via
   `rclone --max-age 168h` on the sync side.
4. **Credentials** — rclone endpoint/key/secret are stored in a dedicated
   Kubernetes Secret (`backup-credentials`) in the `harbor` namespace.

## Non-Goals

- No new Go code — this is pure Kubernetes/infrastructure.
- No Helm chart parameterization — delivered as standalone kustomize resources
  under `deploy/backup/`.
- No cross-region replication — single bucket; operator adds geo-redundancy.
- No encryption-at-rest layering — rely on bucket-side SSE (S3/R2 default).

## Success Criteria

- `kubectl apply --dry-run=client -k deploy/backup/` succeeds with no errors.
- Restore runbook is present and covers both etcd and PostgreSQL restore paths.
- 7-day retention is enforced automatically.
