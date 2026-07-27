# Spec: Offsite etcd + PostgreSQL Backup Requirements

Adds offsite backup for RKE2 etcd snapshots and Harbor PostgreSQL, closing the
single-point-of-failure where both live data and its only backup reside on the
same disk. Delivers a Kubernetes CronJob for etcd snapshot sync (rclone, every
6 h) and a second CronJob for daily `pg_dump` streaming to Cloudflare R2 or
AWS S3, with a 7-day retention policy and a documented restore runbook.

## ADDED Requirements

### Requirement: REQ-001 Etcd snapshots MUST be uploaded offsite every 6 hours

The system SHALL configure RKE2 native `etcd-s3` to upload etcd snapshots to an
offsite S3-compatible bucket on a schedule of at most every 6 hours. A secondary
rclone CronJob SHALL sync the on-disk snapshot directory to the same bucket every
6 hours as a defense-in-depth fallback. Neither path SHALL require a pod to write
to the snapshot directory.

#### Scenario: RKE2 native etcd-s3 uploads a snapshot every 6 hours

**Given** the RKE2 host config has `etcd-snapshot-schedule-cron: "0 */6 * * *"` and
`etcd-s3: true` pointing to the backup bucket
**When** 6 hours elapse from the last snapshot
**Then** a new snapshot object appears in the bucket under the configured folder
and no partial-file race condition is possible (upload is atomic)

#### Scenario: rclone sync CronJob copies any on-disk snapshots not yet in the bucket

**Given** a snapshot file exists in `/var/lib/rancher/rke2/server/db/snapshots/`
(e.g. a manually-triggered `rke2 etcd-snapshot save`)
**When** the `harbor-etcd-sync` CronJob runs
**Then** the snapshot file is uploaded to `r2:harbor-backups/etcd/` and the
CronJob exits 0

#### Scenario: etcd sync pod MUST NOT write to the snapshot directory

**Given** the `harbor-etcd-sync` CronJob pod
**When** it accesses the hostPath volume
**Then** the mount is `readOnly: true` and the pod MUST NOT modify, delete, or
create files in the snapshot directory

### Requirement: REQ-002 PostgreSQL MUST be backed up daily via streaming pg_dump

The system SHALL run a Kubernetes CronJob at 03:00 UTC daily that streams a
`pg_dump -Fc` of the Harbor PostgreSQL database directly to the offsite bucket
under the `db-backups/` prefix. The dump MUST NOT be written to the node
filesystem or any PVC intermediary at any point during the backup operation.

#### Scenario: pg_dump streams to bucket without touching node disk

**Given** the `harbor-pgdump` CronJob runs at 03:00 UTC
**When** the backup completes
**Then** a `.dump` object appears in `r2:harbor-backups/db-backups/` named with
the current UTC date, `pg_restore --list` on the downloaded object succeeds,
and no temporary file exists on the node filesystem

#### Scenario: pg_dump pod reads PGPASSWORD from the existing harbor-postgresql Secret

**Given** the `harbor-pgdump` CronJob spec
**When** the pod starts
**Then** `PGPASSWORD` is injected via `secretKeyRef` pointing to the
`harbor-postgresql` Secret's password key; no plaintext password appears in the
CronJob YAML

### Requirement: REQ-003 Backup retention SHALL be 7 days

The system SHALL enforce a retention window of 7 days (168 hours) for both etcd
snapshots and PostgreSQL dumps in the offsite bucket. Objects older than 7 days
SHALL be eligible for deletion. A bucket lifecycle policy of at most 30 days SHALL
act as a safety-net backstop.

#### Scenario: Objects older than 7 days are pruned by rclone

**Given** rclone is invoked with `--max-age 168h` during the sync or delete pass
**When** the CronJob runs
**Then** objects in the bucket that are older than 168 hours are removed and only
the last 7 days of snapshots and dumps remain

#### Scenario: Bucket lifecycle policy backstops the retention enforcement

**Given** the bucket has a lifecycle policy with expiry ≤ 30 days
**When** the rclone retention pass fails to run (e.g. CronJob is suspended)
**Then** the bucket lifecycle policy eventually removes objects older than 30 days,
preventing unbounded accumulation

### Requirement: REQ-004 Backup credentials SHALL be stored in a Kubernetes Secret

The system SHALL store all bucket access credentials (R2/S3 access key, secret
key, endpoint) in a Kubernetes Secret named `backup-credentials` in the
`harbor-backup` namespace. Credentials MUST NOT appear in any CronJob or
kustomization YAML committed to the repository. The Secret manifest committed to
git SHALL be a placeholder template with no real credential values.

#### Scenario: No credential values appear in committed YAML

**Given** the `deploy/backup/` directory committed to git
**When** the files are inspected
**Then** no R2/S3 access key, secret key, or account ID with real values appears;
all sensitive fields are placeholder strings (e.g. `REPLACE_ME`)

#### Scenario: CronJob pods mount credentials from the Secret

**Given** the `harbor-etcd-sync` and `harbor-pgdump` CronJob specs
**When** a pod starts
**Then** rclone config and PGPASSWORD are populated from `secretKeyRef` or a
volume mount of `backup-credentials`; no credential is hardcoded in the pod spec

### Requirement: REQ-005 Backup pods SHALL run in a dedicated namespace with minimal egress

The system SHALL deploy all backup CronJobs and supporting resources in a
dedicated `harbor-backup` namespace. A NetworkPolicy SHALL restrict egress from
backup pods to DNS (port 53) and HTTPS (port 443) only. No other egress SHALL be
permitted.

#### Scenario: Backup pod egress is limited to DNS and HTTPS

**Given** the NetworkPolicy `backup-egress` applied to the `harbor-backup` namespace
**When** a backup pod attempts to open a connection to any destination other than
DNS (53/UDP) or HTTPS (443/TCP)
**Then** the connection is denied by the NetworkPolicy

#### Scenario: harbor namespace PSA policy is not weakened

**Given** the `harbor` namespace with `pod-security.kubernetes.io/enforce: restricted`
**When** the backup CronJobs are deployed
**Then** they run in `harbor-backup`, not `harbor`, and the `harbor` namespace PSA
policy remains `restricted` and unchanged

### Requirement: REQ-006 All backup resources SHALL be wired into kustomization.yaml

The system SHALL provide a `deploy/backup/kustomization.yaml` that references all
backup resources (namespace, ServiceAccount, NetworkPolicy, Secret template, etcd
sync CronJob, pg_dump CronJob). `kubectl apply --dry-run=client -k deploy/backup/`
MUST exit 0.

#### Scenario: kubectl dry-run succeeds for the full backup directory

**Given** the `deploy/backup/` manifests as committed
**When** `kubectl apply --dry-run=client -k deploy/backup/` is executed against a
cluster with the Kubernetes API available
**Then** the command exits 0 and no validation errors are reported

### Requirement: REQ-007 A restore runbook SHALL be documented and executable

The system SHALL document a restore runbook in `deploy/backup/README.md` covering:
etcd restore from a bucket snapshot using `rke2 server --cluster-reset`, and
PostgreSQL restore using `pg_restore`. The runbook SHALL include bucket setup,
credential scoping, and a verification step. The runbook MUST be executable
against a scratch environment before this feature is marked complete.

#### Scenario: Operator can restore PostgreSQL from a dump object

**Given** a `.dump` object in the bucket
**When** the operator follows the runbook step-by-step
**Then** `pg_restore -d harbor --clean --if-exists <dump>` succeeds and the
database is in a consistent state matching the backup point

#### Scenario: Operator can restore etcd from a bucket snapshot

**Given** a snapshot object in `r2:harbor-backups/etcd/`
**When** the operator follows the runbook step-by-step
**Then** `rke2 server --cluster-reset --cluster-reset-restore-path=<snapshot>`
(with S3 flags to pull from the bucket) restores the cluster state successfully
