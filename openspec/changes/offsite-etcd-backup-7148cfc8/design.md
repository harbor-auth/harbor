# Design: Offsite etcd + PostgreSQL backup

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Kubernetes cluster (harbor namespace)                       │
│                                                              │
│  ┌─────────────────────────┐  ┌──────────────────────────┐  │
│  │ CronJob: etcd-backup    │  │ CronJob: pgdump-backup   │  │
│  │ schedule: 0 */6 * * *   │  │ schedule: 0 3 * * *      │  │
│  │ image: rclone/rclone    │  │ image: postgres:16        │  │
│  │                         │  │                           │  │
│  │ mounts hostPath:        │  │ reads: harbor-postgresql  │  │
│  │  /var/lib/rancher/rke2/ │  │ Secret (POSTGRES_PASSWORD)│  │
│  │  server/db/snapshots/   │  │                           │  │
│  └────────────┬────────────┘  └───────────┬───────────────┘  │
│               │                           │                  │
│  ┌────────────▼───────────────────────────▼────────────────┐ │
│  │ Secret: backup-credentials                              │ │
│  │  RCLONE_CONFIG_R2_TYPE=s3                               │ │
│  │  RCLONE_CONFIG_R2_PROVIDER=Cloudflare                   │ │
│  │  RCLONE_CONFIG_R2_ACCESS_KEY_ID=<key>                   │ │
│  │  RCLONE_CONFIG_R2_SECRET_ACCESS_KEY=<secret>            │ │
│  │  RCLONE_CONFIG_R2_ENDPOINT=<r2-endpoint>                │ │
│  │  BACKUP_BUCKET=<bucket-name>                            │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
                         │
                         ▼
              S3 / Cloudflare R2 bucket
              ├── etcd-snapshots/          (written by rclone sync)
              └── db-backups/              (written by rclone copyto)
```

## Key Decisions

### D1: rclone over aws s3 sync

rclone supports both AWS S3 and Cloudflare R2 via the same s3-compatible backend.
Using rclone means the same CronJob image works with either provider — the operator
sets `RCLONE_CONFIG_R2_TYPE=s3` and `RCLONE_CONFIG_R2_PROVIDER` to switch. aws-cli
would require a separate install for R2 compatibility.

### D2: hostPath volume for etcd snapshots

RKE2 writes snapshots to `/var/lib/rancher/rke2/server/db/snapshots/` on the
control-plane node. The CronJob uses `hostPath` with `nodeAffinity` pinning to the
control-plane node (label `node-role.kubernetes.io/control-plane: "true"`).
This is intentional — the snapshot files only exist on the control-plane.

### D3: RKE2 native etcd-s3 as a complementary mechanism

RKE2's built-in `etcd-snapshot-schedule-cron` + `etcd-s3-*` flags can write
snapshots directly to S3 without an extra CronJob. The design ships a config
snippet (`rke2-etcd-s3-snippet.yaml`) documenting this as an alternative, but
the primary delivery is the CronJob (works even without RKE2 etcd-s3 support).

### D4: pg_dump via existing harbor-postgresql Secret

The harbor-postgresql Helm chart (Bitnami pattern) exposes the password via a
Secret named `harbor-postgresql` with key `postgres-password`. The pg_dump
CronJob mounts this Secret and uses the standard harbor Service DNS name
`harbor-postgresql.harbor.svc.cluster.local` on port 5432.

### D5: Retention enforced client-side

`rclone sync --max-age 168h` (7 days = 168 hours) removes files older than 7
days from the remote during sync. For pg_dump (which uses `rclone copyto`), a
separate `rclone delete --min-age 168h` step runs after the upload.

### D6: Credentials in a dedicated Secret

A single `backup-credentials` Secret holds all rclone config env-vars and the
bucket name. The pg_dump CronJob mounts both this Secret and the existing
`harbor-postgresql` Secret (read-only). No secrets are baked into the image.

### D7: No new Go code

This feature is purely Kubernetes manifests. The existing Go codebase is
unaffected. Validation is via `kubectl apply --dry-run=client -k deploy/backup/`
plus `go build ./... && go test ./...` to confirm no regressions.

## File Layout

```
deploy/backup/
├── kustomization.yaml          # wires all resources
├── secret-backup.yaml          # backup-credentials Secret (placeholder values)
├── cronjob-etcd.yaml           # etcd snapshot rclone sync CronJob
├── cronjob-pgdump.yaml         # pg_dump + rclone upload CronJob
├── rke2-etcd-s3-snippet.yaml   # RKE2 native etcd-s3 config (informational)
└── README.md                   # restore runbook + retention policy

docs/plans/
└── offsite-etcd-backup.md      # plan-of-record

openspec/changes/offsite-etcd-backup-7148cfc8/
├── proposal.md
├── design.md
├── specs/backup-requirements.md
└── tasks.md
```
