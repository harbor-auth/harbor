# Design: Offsite etcd + PostgreSQL Backup

## Key Decisions

### Decision 1: RKE2-native `etcd-s3` as primary etcd backup path
**Chosen:** Configure `etcd-snapshot-schedule-cron` and `etcd-s3` flags in
`/etc/rancher/rke2/config.yaml`; snapshots are taken and uploaded atomically by
RKE2 every 6 hours.
**Rationale:** RKE2's native S3 integration ensures snapshot-taking and upload are
a single atomic operation in one code path. A CronJob that races with an in-progress
snapshot file on a hostPath mount risks uploading a corrupt partial snapshot. The
native path has no such race. It is also simpler — no Kubernetes pod needs host
filesystem access for the primary path.
**Alternatives considered:** hostPath CronJob as primary (rejected — race with
in-progress snapshot files, requires privileged pod); rclone-only (rejected —
cannot take a snapshot, only copies already-complete files).

### Decision 2: rclone sync CronJob as defense-in-depth fallback
**Chosen:** A secondary CronJob in `harbor-backup` namespace syncs
`/var/lib/rancher/rke2/server/db/snapshots/` to the bucket via rclone every 6
hours. This covers manually-taken snapshots and acts as a belt to the `etcd-s3`
suspenders.
**Rationale:** The native `etcd-s3` path is the primary; the sync CronJob catches
snapshots that exist on disk but were not uploaded (e.g. manual `rke2
etcd-snapshot save`, operator-initiated snapshots before the native config was
applied). A secondary copy path adds resilience at low operational cost.
**Alternatives considered:** Single path only (rejected — no defence-in-depth);
systemd timer on the host (rejected — harder to manage via GitOps, harder to
alert on).

### Decision 3: Cloudflare R2 as the default bucket target
**Chosen:** R2 (`<accountid>.r2.cloudflarestorage.com`) is the preferred target;
AWS S3 is the drop-in alternative.
**Rationale:** R2 has zero egress fees (critical for a daily pg_dump that may
reach several hundred MB), is S3-API-compatible (all tooling — rclone, aws CLI,
wal-g — works unchanged), and uses credentials already provisioned in the
Cloudflare account used for DNS-01 certificate issuance. Switching to AWS S3
requires only changing endpoint and region in the config.
**Alternatives considered:** AWS S3 as default (rejected — egress costs add up;
no pre-existing account relationship); MinIO in-cluster (rejected — defeats the
purpose of offsite backup).

### Decision 4: Stream pg_dump directly to the bucket; never land on disk
**Chosen:** `pg_dump -Fc ... | rclone rcat remote:bucket/db-backups/...` streams
the dump directly to the bucket without writing a temporary file to the node
filesystem.
**Rationale:** A node-resident dump file is PII at rest on a node disk. Streaming
eliminates the window where the dump exists on disk, reduces disk pressure (no
need for a PVC large enough to hold a full dump), and avoids the failure mode
where the disk fills up mid-dump and the file is corrupt.
**Alternatives considered:** Dump to PVC then upload (rejected — PII at rest on
disk, PVC sizing risk); dump to emptyDir then upload (rejected — still PII on
disk, requires cleanup job on failure).

### Decision 5: Separate `harbor-backup` namespace with PSA `privileged`
**Chosen:** The etcd sync CronJob requires a `hostPath` read-only mount to access
`/var/lib/rancher/rke2/server/db/snapshots/`; this cannot satisfy PSA
`restricted`. A dedicated `harbor-backup` namespace with
`pod-security.kubernetes.io/enforce: privileged` is created for it, with its own
ServiceAccount and a tight NetworkPolicy (egress: DNS + 443 only).
**Rationale:** Weakening the `harbor` namespace's PSA `restricted` policy for one
pod would degrade the security posture for all pods in the namespace. A dedicated
namespace scopes the privilege grant and makes the exception explicit and auditable.
**Alternatives considered:** Run in `harbor` namespace with restricted PSA (not
possible — hostPath mounts require non-restricted pod); run as a DaemonSet
(rejected — overkill for a single-node cluster, same privilege concern).

### Decision 6: 7-day retention via rclone `--max-age 168h`
**Chosen:** Retention is enforced by passing `--max-age 168h` to rclone on the
sync side, combined with bucket lifecycle policies (30-day expiry as a safety net).
**Rationale:** Seven days at a 6-hour cadence yields 28 etcd snapshot copies; for
pg_dump it yields 7 daily copies. This covers the most likely incident scenario
(detected within a few days). The bucket lifecycle policy (30-day expiry) acts as
a backstop if the rclone flag is misconfigured.
**Alternatives considered:** Bucket-only lifecycle policies (rejected — no
guarantee rclone deletes old files before they accumulate; harder to test);
longer retention (rejected — cost scales with dump size; 7 days covers the
realistic detection window).

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  RKE2 host  (/etc/rancher/rke2/config.yaml)                                  │
│    etcd-snapshot-schedule-cron: "0 */6 * * *"                               │
│    etcd-s3: true  → uploads atomically to R2/S3  ────────────────────────► │
│    etcd-snapshot-retention: 28                                               │
└──────────────────────────────────────────────────────────────────────────────┘
                          (primary path)

┌────────────────────────────────────────────────────────────────────────────────┐
│  harbor-backup namespace                                                       │
│                                                                                │
│  CronJob: harbor-etcd-sync  (every 6h)                                        │
│    hostPath: /var/lib/rancher/rke2/server/db/snapshots/ (readOnly)            │
│    rclone sync → r2:harbor-backups/etcd/  ────────────────────────────────►  │
│    --max-age 168h                                                              │
│                                                                                │
│  CronJob: harbor-pgdump  (daily 03:00 UTC)                                    │
│    pg_dump -Fc | rclone rcat → r2:harbor-backups/db-backups/<date>.dump ───► │
│    PGHOST=harbor-postgresql  PGPASSWORD from harbor-postgresql Secret          │
│    --max-age 168h                                                              │
│                                                                                │
│  Secret: backup-credentials  (rclone config: R2 access key + secret)          │
│  NetworkPolicy: egress DNS(53) + HTTPS(443) only                               │
└────────────────────────────────────────────────────────────────────────────────┘

                    ▼
         Cloudflare R2 (or AWS S3)
         harbor-backups/
           etcd/          ← RKE2 native + rclone sync
           db-backups/    ← pg_dump stream
```

## Security Properties

- Credentials are stored in a Kubernetes Secret, never in manifests or image layers.
- The etcd sync pod has a `readOnly: true` hostPath mount; it cannot write to the
  snapshot directory.
- The pg_dump pod reads `PGPASSWORD` from the existing `harbor-postgresql` Secret
  via `secretKeyRef`; no password appears in the CronJob spec.
- Both pods have a NetworkPolicy that permits egress only to DNS (53) and HTTPS
  (443). No other egress is permitted.
- Bucket credentials should be scoped to write-only + list on the backup prefix;
  the backup account MUST NOT have `s3:DeleteObject` where the bucket supports
  object lock.
- Dumps contain PII; phase 1 relies on R2/S3 SSE. Client-side `age` encryption
  is a documented fast-follow (tracked in `infra-hardening.md`).
