# Proposal: Offsite etcd + PostgreSQL Backup

## Problem

RKE2 takes snapshots of etcd to `/var/lib/rancher/rke2/server/db/snapshots/` on a
daily schedule, but those snapshots live **on the same disk as the live data**. A
single disk failure, node compromise, or ransomware event destroys both the cluster
state and its only copy simultaneously. Worse, etcd holds only Kubernetes *cluster*
state — Harbor's application data (users, WebAuthn credentials, consent ledger,
audit trail, client registrations) lives in **PostgreSQL**, which currently has
**no backup at all**. Losing the Postgres volume permanently locks out every enrolled
user because passkeys are the primary authentication factor and there is no email
recovery backdoor.

## Proposed Solution

1. **etcd → R2/S3 via RKE2 native `etcd-s3`** — configure
   `etcd-snapshot-schedule-cron` and `etcd-s3` flags in the host-level RKE2 config;
   snapshots are uploaded atomically by RKE2 every 6 hours. Documented as a
   cluster-ops runbook step (ArgoCD cannot manage host files).
2. **etcd rclone sync CronJob** *(defense-in-depth fallback)* — a Kubernetes CronJob
   in a dedicated `harbor-backup` namespace syncs
   `/var/lib/rancher/rke2/server/db/snapshots/` to the bucket via rclone every 6
   hours, covering manually-taken snapshots and acting as a secondary copy path.
3. **PostgreSQL → daily `pg_dump` CronJob** — a second CronJob streams
   `pg_dump -Fc` output directly to the bucket under `db-backups/` at 03:00 UTC
   daily. No dump file lands on the node filesystem. rclone `--max-age 168h` enforces
   a 7-day retention window.
4. **Credentials Secret + kustomization** — credentials are stored in a
   `backup-credentials` Kubernetes Secret (template only; values from
   `~/.harbor.env`). All resources are wired into `deploy/backup/kustomization.yaml`.
5. **Restore runbook** — `deploy/backup/README.md` documents bucket creation,
   credential scoping, the RKE2 host config apply, and step-by-step restore
   procedures for both etcd and PostgreSQL.

## Non-Goals

- **WAL archiving / point-in-time recovery** — phase 1 ships `pg_dump` only; WAL
  archiving with `wal-g` is a documented fast-follow, not a blocker.
- **Client-side encryption of dumps** — phase 1 relies on R2/S3 SSE; `age`
  client-side encryption is a documented fast-follow.
- **External Secrets Operator** — credentials live in a static Secret template for
  now; ESO migration is tracked in the `kms-credentials-rotation` plan.
- **Multi-region replication** — the bucket is the offsite store; cross-region
  replication within R2/S3 is an operator concern outside this plan.
- **Go code changes** — this feature is purely Kubernetes manifests, config
  snippets, and documentation; no Go source files are modified.

## Success Criteria

- [ ] `kubectl apply --dry-run=client -k deploy/backup/` exits 0.
- [ ] etcd snapshots appear in the bucket within 6 hours of host config apply.
- [ ] A pg_dump object appears in the bucket within 24 hours of CronJob deploy.
- [ ] `pg_restore --list` on a downloaded dump succeeds.
- [ ] Restore runbook is documented and executable against a scratch Postgres.
- [ ] `go build ./... && go vet ./... && go test ./... && make agent-check` green
  (no Go changes; must remain green).
