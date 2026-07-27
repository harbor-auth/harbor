# Spec: Offsite etcd + PostgreSQL backup requirements

## ADDED Requirements

### REQ-001: etcd snapshot offsite sync

The system SHALL provide a Kubernetes CronJob (`etcd-backup`) that runs every 6
hours and syncs all files from the RKE2 etcd snapshot directory
(`/var/lib/rancher/rke2/server/db/snapshots/`) to the configured S3-compatible
bucket under the prefix `etcd-snapshots/`.

The CronJob MUST:
- Pin to the control-plane node via `nodeAffinity`
- Mount the snapshot directory as a read-only `hostPath` volume
- Source rclone credentials exclusively from the `backup-credentials` Secret
- Remove remote files older than 7 days (168 h) during sync
- Set `concurrencyPolicy: Forbid` to prevent overlapping runs

The CronJob MUST NOT:
- Bake any credentials into the container image or manifest
- Run with elevated privileges beyond what rclone requires

#### Scenario: Successful etcd sync

**Given** the CronJob `etcd-backup` fires at its scheduled time  
**And** the `backup-credentials` Secret contains valid rclone env-vars  
**And** the snapshot directory contains at least one `.zip` or `.db` file  
**When** the Job Pod completes  
**Then** the Pod exits with code 0  
**And** the snapshot files are present in the bucket under `etcd-snapshots/`  
**And** any files older than 7 days are absent from the remote  

#### Scenario: Missing credentials Secret

**Given** the `backup-credentials` Secret does not exist  
**When** the Job Pod starts  
**Then** the Pod fails to start (Secret mount error) with a descriptive event  
**And** no data is uploaded  

---

### REQ-002: PostgreSQL daily backup

The system SHALL provide a Kubernetes CronJob (`pgdump-backup`) that runs daily
at 03:00 UTC, performs a compressed `pg_dump` of the `harbor` database, and
uploads the dump to the bucket under `db-backups/harbor-YYYY-MM-DD.dump.gz`.

The CronJob MUST:
- Source the PostgreSQL password from the existing `harbor-postgresql` Secret
  (key: `postgres-password`)
- Connect to `harbor-postgresql.harbor.svc.cluster.local:5432` as `harbor`
- Upload via `rclone copyto` (not sync, to preserve historical dumps)
- Prune dumps older than 7 days using `rclone delete --min-age 168h`
- Set `concurrencyPolicy: Forbid`

#### Scenario: Successful pg_dump upload

**Given** the `pgdump-backup` CronJob fires at 03:00 UTC  
**And** the `harbor-postgresql` and `backup-credentials` Secrets exist  
**And** the PostgreSQL service is reachable  
**When** the Job Pod completes  
**Then** the Pod exits with code 0  
**And** a file named `harbor-<today>.dump.gz` is present under `db-backups/` in the bucket  
**And** dumps older than 7 days have been removed from `db-backups/`  

---

### REQ-003: Credentials isolation

The system SHALL store all rclone remote configuration (endpoint, access key,
secret key, bucket name) in a single dedicated Kubernetes Secret
(`backup-credentials`).

The Secret MUST NOT be included in source control with real values —
placeholder values MUST be used in the committed manifest.

#### Scenario: Secret contains placeholder values

**Given** the `secret-backup.yaml` file is committed to the repository  
**When** a reviewer inspects the file  
**Then** all sensitive values are the literal string `CHANGEME` or equivalent placeholder  

---

### REQ-004: Kustomize wiring

The system SHALL wire all backup resources (Secrets, CronJobs) into
`deploy/backup/kustomization.yaml` so that a single
`kubectl apply -k deploy/backup/` applies the complete backup stack.

#### Scenario: Dry-run apply succeeds

**Given** a `kubectl` binary with access to a cluster API (or `--dry-run=client`)  
**When** `kubectl apply --dry-run=client -k deploy/backup/` runs  
**Then** the command exits with code 0 with no errors  

---

### REQ-005: Restore runbook

The system SHALL include `deploy/backup/README.md` with:
- A step-by-step etcd restore procedure using `rclone copy` + `rke2 etcd-snapshot restore`
- A step-by-step PostgreSQL restore procedure using `rclone copy` + `pg_restore`
- The retention policy (7 days)
- Credential setup instructions

#### Scenario: Runbook coverage

**Given** the `deploy/backup/README.md` exists  
**When** a reviewer reads it  
**Then** it contains headings for both etcd restore and PostgreSQL restore  
**And** it states the 7-day retention policy  
