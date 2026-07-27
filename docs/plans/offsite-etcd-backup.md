# Plan — Offsite etcd + PostgreSQL Backup (`offsite-etcd-backup`)

> **Status:** draft · **Tier:** T2.1 (infra-hardening) · **Target cluster:** `51.89.98.90`
> (`ns31170412`, RKE2 v1.35.6, single-node) · **Parent doc:** [`infra-hardening.md`](infra-hardening.md#t21--offsite-etcd-backup)

## 1. Problem statement

RKE2 takes daily etcd snapshots to `/var/lib/rancher/rke2/server/db/snapshots/`, but they
live **on the same disk as the live data**. A disk failure, node compromise, or ransomware
event destroys both the cluster state and its only backup simultaneously. Worse, etcd only
holds *cluster* state — Harbor's actual crown jewels (users, WebAuthn credentials, consent
ledger, audit trail, client registrations) live in **PostgreSQL**, which today has **no
backup at all**. Losing the Postgres volume permanently locks out every enrolled user
(passkeys are the primary factor; there is no email backdoor).

Recovery objectives this plan targets:

| Store | RPO | RTO | Mechanism |
|---|---|---|---|
| etcd (cluster state) | ≤ 6 h | ≤ 1 h | RKE2 `etcd-s3` snapshot upload every 6 h |
| PostgreSQL (app data) | ≤ 24 h base, ≤ 5 min with WAL | ≤ 2 h | daily `pg_dump` CronJob + continuous WAL archiving to S3/R2 |

## 2. Approach

### 2.1 etcd → S3/R2 via RKE2 native `etcd-s3` (host config, documented; not a manifest)

RKE2 has first-class S3 snapshot upload. This is host-level config in
`/etc/rancher/rke2/config.yaml`, applied by the operator (documented here, executed as a
cluster-ops step — ArgoCD cannot manage host files):

```yaml
etcd-snapshot-schedule-cron: "0 */6 * * *"   # every 6 hours
etcd-snapshot-retention: 28                   # 7 days at 6h cadence
etcd-s3: true
etcd-s3-endpoint: <R2-or-S3-endpoint>         # R2: <accountid>.r2.cloudflarestorage.com
etcd-s3-bucket: harbor-etcd-backups
etcd-s3-region: auto                          # R2 uses "auto"; S3 uses real region
etcd-s3-folder: ns31170412
etcd-s3-access-key: <from ~/.harbor.env — never commit>
etcd-s3-secret-key: <from ~/.harbor.env — never commit>
```

Then `sudo systemctl restart rke2-server`. **Cloudflare R2 is the preferred target**
(S3-compatible, no egress fees, credentials already provisioned in the Cloudflare account
used for DNS-01). AWS S3 is the drop-in alternative — the config differs only in
endpoint/region.

### 2.2 PostgreSQL → daily `pg_dump` CronJob + WAL archiving (Kubernetes manifests, in-repo)

New manifests under `deploy/backup/`:

- **`cronjob-pgdump.yaml`** — daily `pg_dump -Fc` (custom format, compressed, supports
  `pg_restore` selective restore) from `harbor-postgresql`, streamed directly to the bucket
  via the awscli/rclone image — **no PVC intermediary**, no dump-at-rest on node disk.
  Schedule `0 3 * * *`. `restartPolicy: OnFailure`, `backoffLimit: 2`,
  `activeDeadlineSeconds: 1800`, `concurrencyPolicy: Forbid`.
- **`cronjob-etcd-sync.yaml`** *(defense-in-depth fallback)* — every 6 h, `aws s3 sync`
  of `/var/lib/rancher/rke2/server/db/snapshots/` to the bucket. This is the belt to the
  `etcd-s3` suspenders and also covers manually-taken snapshots. Requires a `hostPath`
  read-only mount → this pod **cannot** run under PSA `restricted`, so it lives in a new
  `harbor-backup` namespace with PSA `privileged` label, its own ServiceAccount, and a
  tight NetworkPolicy (egress: DNS + 443 only).
- **`secret-backup-credentials.yaml`** — template-only (values from `~/.harbor.env`,
  never committed; long-term superseded by ESO — see `kms-credentials-rotation` plan).
- **`networkpolicy-backup.yaml`**, **`namespace.yaml`**, **`kustomization.yaml`**.

WAL archiving: enable `archive_mode = on` and
`archive_command = 'wal-g wal-push %p'` (or `archive_timeout = 300` with a simple
S3-push script) on the Postgres deployment via its config. If the chart in use makes
`postgresql.conf` overrides awkward, phase 1 ships `pg_dump` only and WAL archiving lands
as a documented follow-up with `wal-g` sidecar — do **not** block the daily dump on it.

### 2.3 Key decisions

1. **RKE2-native `etcd-s3` over a pure CronJob** for etcd: snapshot-taking and upload
   are atomic in one code path; no hostPath race with in-progress snapshot files. The
   sync CronJob is a secondary copy path, not the primary.
2. **R2 over S3** as default target: zero egress cost, existing Cloudflare account, S3
   API-compatible so all tooling (`aws` CLI, wal-g) works unchanged.
3. **Stream dumps, never land on disk**: `pg_dump | aws s3 cp - s3://…` keeps PII off
   the node filesystem and out of any PVC.
4. **Separate `harbor-backup` namespace**: the hostPath sync job cannot satisfy
   `restricted` PSA; do not weaken the `harbor` namespace for it.
5. **Bucket hygiene**: enable object-lock/versioning + 30-day lifecycle expiry on the
   bucket; backup credentials get a bucket-scoped, write-mostly policy (no
   `s3:DeleteObject` where the target supports it) so a compromised node cannot destroy
   history.
6. **Encryption**: dumps contain PII → pipe through `age`/`gpg` symmetric encryption with
   a key held outside the cluster, OR rely on R2/S3 SSE + strict bucket policy. Ship SSE
   in phase 1; client-side `age` encryption as fast-follow.

## 3. Implementation steps

1. Create `deploy/backup/` with namespace, ServiceAccount, NetworkPolicy, credentials
   Secret template, `cronjob-pgdump.yaml`, `cronjob-etcd-sync.yaml`, kustomization.
2. Document the RKE2 `etcd-s3` host config block + rollout steps in this plan and in
   `deploy/backup/README.md` (operator runbook: bucket creation, credential scoping,
   config apply, restart, verification).
3. Add restore runbooks to `deploy/backup/README.md`:
   - etcd: `rke2 server --cluster-reset --cluster-reset-restore-path=<snapshot>` (with
     the S3 flags to pull directly from the bucket).
   - Postgres: `pg_restore -d harbor --clean --if-exists <dump>`; WAL replay procedure
     once archiving lands.
4. Wire `deploy/backup/` into the ArgoCD app-of-apps (or a standalone Application
   manifest committed alongside).

## 4. Validation

- `kubectl apply --dry-run=client -k deploy/backup/` clean.
- `kubeconform`/schema-sane YAML; `helm lint` unaffected (chart untouched or, if
  templated into the chart instead, lint green).
- Manual trigger: `kubectl create job --from=cronjob/harbor-pgdump pgdump-test -n harbor-backup`
  → object appears in bucket; `pg_restore --list` on the downloaded dump succeeds.
- `rke2 etcd-snapshot save` (post host-config) → snapshot visible in bucket.
- **Restore drill documented and executed once** against a scratch Postgres before this
  item is marked complete — an unrestored backup is not a backup.
- Repo checks: `go build ./... && go vet ./... && go test ./... && make agent-check` green
  (no Go changes expected; must stay green).
