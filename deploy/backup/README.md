# Harbor Backup — Restore Runbook & Retention Policy

This directory contains the Kubernetes manifests and configuration for Harbor's
offsite backup stack (T2.1 infra hardening).

## Contents

| File | Purpose |
|---|---|
| `secret-backup.yaml` | Template for `backup-credentials` Secret (rclone S3/R2 config) |
| `cronjob-etcd.yaml` | CronJob: rclone-sync etcd snapshots → R2 every 6 h |
| `cronjob-pgdump.yaml` | CronJob: pg\_dump harbor DB → R2 daily at 03:00 UTC |
| `kustomization.yaml` | Kustomize entry-point: `kubectl apply -k deploy/backup/` |
| `rke2-etcd-s3-snippet.yaml` | Informational: RKE2 native etcd-s3 config flags (not a K8s resource) |

---

## Retention Policy

| Backup type | Schedule | Kept for | Enforcement |
|---|---|---|---|
| etcd snapshots | Every 6 h | **7 days (168 h)** | `rclone --max-age 168h` in harbor-etcd-sync |
| PostgreSQL dumps | Daily 03:00 UTC | **7 days (168 h)** | `rclone delete --min-age 168h` in harbor-pgdump |
| Local etcd snapshots | Every 6 h | 5 snapshots | `etcd-snapshot-retention: 5` in RKE2 config |

Bucket layout:

```
r2:harbor-backups/
  etcd/          ← RKE2 native upload + rclone sync
  db-backups/    ← pg_dump custom-format, gzip-compressed
```

---

## Credential Setup (one-time)

### 1. Create the harbor-backup namespace

```bash
kubectl create namespace harbor-backup
kubectl label namespace harbor-backup \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/warn=privileged
kubectl create serviceaccount harbor-backup -n harbor-backup
```

### 2. Populate the backup-credentials Secret

Retrieve real values from `~/.harbor.env`, then:

```bash
kubectl create secret generic backup-credentials \
  --namespace=harbor-backup \
  --from-literal=RCLONE_CONFIG_R2_TYPE=s3 \
  --from-literal=RCLONE_CONFIG_R2_PROVIDER=Cloudflare \
  --from-literal=RCLONE_CONFIG_R2_ACCESS_KEY_ID=<ACCESS_KEY> \
  --from-literal=RCLONE_CONFIG_R2_SECRET_ACCESS_KEY=<SECRET_KEY> \
  --from-literal=RCLONE_CONFIG_R2_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com \
  --from-literal=RCLONE_CONFIG_R2_REGION=auto \
  --from-literal=BACKUP_BUCKET=harbor-backups \
  --dry-run=client -o yaml | kubectl apply -f -
```

For **AWS S3** instead of Cloudflare R2: set `PROVIDER=AWS` and
`ENDPOINT=https://s3.<region>.amazonaws.com` (or omit ENDPOINT for us-east-1).

### 3. Apply the backup stack

```bash
kubectl apply -k deploy/backup/
```

### 4. (Optional) Enable RKE2 native etcd-s3 upload

See `rke2-etcd-s3-snippet.yaml` for the config block to merge into
`/etc/rancher/rke2/config.yaml` on each control-plane node.

---

## Verify Backups are Running

```bash
# Check CronJob status
kubectl get cronjobs -n harbor-backup

# List recent Jobs
kubectl get jobs -n harbor-backup --sort-by=.metadata.creationTimestamp

# Tail the last etcd-sync run
kubectl logs -n harbor-backup \
  $(kubectl get pods -n harbor-backup -l app.kubernetes.io/name=harbor-etcd-sync \
    --sort-by=.metadata.creationTimestamp -o name | tail -1)

# List objects in bucket (requires rclone configured locally)
rclone ls r2:harbor-backups/etcd/ | sort
rclone ls r2:harbor-backups/db-backups/ | sort
```

---

## Restore Runbook — etcd

> **Use this procedure when the cluster control plane is lost or corrupted.**
> Estimated time: 20–40 minutes.

### Prerequisites

- SSH access to a RKE2 control-plane node (root or sudo)
- `rclone` installed and configured with R2 credentials (or use `aws s3 cp`)
- All other control-plane nodes stopped

### Steps

**1. Identify the snapshot to restore**

```bash
rclone ls r2:harbor-backups/etcd/ | sort -k2
# Output: <size> etcd/<snapshot-name>.db
```

Choose the most recent healthy snapshot. Note the full object key
(e.g. `etcd/etcd-snapshot-2026-07-25T06:00:00Z.db`).

**2. Copy the snapshot to the bootstrap control-plane node**

```bash
SNAPSHOT="etcd-snapshot-2026-07-25T06:00:00Z.db"
rclone copy \
  "r2:harbor-backups/etcd/${SNAPSHOT}" \
  /var/lib/rancher/rke2/server/db/snapshots/
```

**3. Stop rke2-server on ALL control-plane nodes**

```bash
# Run on every control-plane node:
systemctl stop rke2-server
```

**4. Reset and restore on the FIRST (bootstrap) control-plane node**

```bash
rke2 server \
  --cluster-reset \
  --cluster-reset-restore-path=/var/lib/rancher/rke2/server/db/snapshots/${SNAPSHOT}
```

Wait for the process to exit with `Cluster reset complete`. This rewrites etcd
data in place; it does **not** start the server.

**5. Start rke2-server on the bootstrap node**

```bash
systemctl start rke2-server
# Verify:
kubectl get nodes
```

**6. Re-join remaining control-plane nodes**

On each additional control-plane node:

```bash
# Remove stale etcd data:
rm -rf /var/lib/rancher/rke2/server/db/etcd
# Start rke2-server (will join existing cluster):
systemctl start rke2-server
```

**7. Verify cluster health**

```bash
kubectl get nodes
kubectl get pods -A | grep -v Running | grep -v Completed
```

---

## Restore Runbook — PostgreSQL

> **Use this procedure to restore the Harbor registry database from a pg\_dump
> backup.**  Estimated time: 10–30 minutes (depends on dump size).

### Prerequisites

- Access to a node/pod that can reach the `harbor-postgresql` Service
- `rclone` and `pg_restore` available
- Harbor application stopped or scaled down to 0 replicas to avoid write conflicts

### Steps

**1. Identify the dump to restore**

```bash
rclone ls r2:harbor-backups/db-backups/ | sort -k2
# Output: <size> db-backups/harbor-YYYY-MM-DD.dump.gz
```

**2. Scale down Harbor to prevent writes**

```bash
kubectl scale deploy -n harbor --all --replicas=0
# Wait for pods to terminate:
kubectl get pods -n harbor -w
```

**3. Download and decompress the dump**

```bash
DATE="2026-07-25"
rclone copy \
  "r2:harbor-backups/db-backups/harbor-${DATE}.dump.gz" \
  /tmp/
gunzip /tmp/harbor-${DATE}.dump.gz
# Result: /tmp/harbor-${DATE}.dump  (pg_dump custom format)
```

**4. Drop and recreate the target database**

```bash
PGPASSWORD="<postgres-password>" psql \
  -h harbor-postgresql.harbor.svc.cluster.local \
  -U postgres \
  -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='registry' AND pid <> pg_backend_pid();"

PGPASSWORD="<postgres-password>" psql \
  -h harbor-postgresql.harbor.svc.cluster.local \
  -U postgres \
  -c "DROP DATABASE IF EXISTS registry; CREATE DATABASE registry OWNER postgres;"
```

**5. Restore**

```bash
PGPASSWORD="<postgres-password>" pg_restore \
  --host=harbor-postgresql.harbor.svc.cluster.local \
  --port=5432 \
  --username=postgres \
  --dbname=registry \
  --no-password \
  --verbose \
  /tmp/harbor-${DATE}.dump
```

**6. Scale Harbor back up**

```bash
kubectl scale deploy -n harbor --all --replicas=1
kubectl get pods -n harbor -w
```

**7. Verify Harbor**

Open the Harbor web UI and confirm repositories, projects, and users are intact.

---

## Bucket Lifecycle (R2 / S3)

In addition to rclone-side pruning, configure a bucket lifecycle rule to
automatically expire objects as a safety net:

**Cloudflare R2** — set via the R2 dashboard:
- Prefix: `etcd/` → expire after **7 days**
- Prefix: `db-backups/` → expire after **7 days**

**AWS S3** — via CLI:

```bash
aws s3api put-bucket-lifecycle-configuration \
  --bucket harbor-backups \
  --lifecycle-configuration '{
    "Rules": [
      {"ID":"etcd-7d","Filter":{"Prefix":"etcd/"},"Status":"Enabled",
       "Expiration":{"Days":7}},
      {"ID":"db-7d","Filter":{"Prefix":"db-backups/"},"Status":"Enabled",
       "Expiration":{"Days":7}}
    ]
  }'
```

---

## Related Documents

- `rke2-etcd-s3-snippet.yaml` — RKE2 native etcd-s3 configuration reference
- `docs/plans/offsite-etcd-backup.md` — design plan and decisions
- `docs/infra-hardening.md` — T2 hardening roadmap
