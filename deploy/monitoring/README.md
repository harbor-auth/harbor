# Production monitoring

ilert receives fixed service names and failure/recovery summaries. It receives no
application logs, user identifiers, tokens, or key material. Three separate API
alert sources cover critical internal checks, low priority warnings, and external
availability. Only each source's event integration key goes to its producer; the
ilert administration API key must never be installed on production or in CI.

The core VM runs `harbor-monitor.timer` every minute. Three consecutive failures
create an alert; the first healthy sample resolves it. Successful deliveries are
recorded under `/var/lib/harbor-monitor` to suppress duplicates. Unsuccessful
deliveries are retried. The monitor pings ilert only when all critical checks pass.
A missing heartbeat for five minutes raises an independent alert, including when
the VM cannot reach ilert, the monitor crashes, or automatic reboot recovery fails.
OpenBao's StatefulSet readiness probe detects its sealed state.

Critical checks cover Harbor hot/management, PostgreSQL, Redis, OpenBao, ingress,
node readiness, and less than 5% available space on the core root filesystem.
Warnings cover node pressure, less than 20% available space, certificate expiry
within 21 days, and monitoring/OVH credentials expiring within 30 days. This does
not inspect the hypervisor's separate filesystems or the cloud VM's internal
workloads. It is not a dependency vulnerability scanner.

`production-monitor.yml` checks public auth health, nonempty JWKS, the website,
and portal from GitHub Actions. Failed checks are retried twice over 40 seconds.
Events are deduplicated by stable alert key; healthy checks submit recovery events.
The nominal schedule is five minutes, but GitHub cron is best effort and may be
delayed or skipped. It is not a strict detection-time guarantee or a complete
login journey. The independent ilert heartbeat remains active during GitHub delays.
Public repositories may have scheduled workflows disabled after inactivity; check
the workflow remains enabled and recent runs exist during operational reviews.

## Installation

Apply `rbac.yaml` to the core cluster. The dedicated service account can read named
workloads and list nodes/certificate metadata. It cannot read Secrets, execute in
pods, mutate workloads, or proxy the node API. Issue a bounded service account
token with `kubectl -n harbor create token harbor-monitor --duration=8760h` and
record its actual JWT expiration; the server may shorten the requested lifetime.

Install `check.py` as root-owned `/opt/harbor-monitor/check.py` (0644), the two
systemd files in `/etc/systemd/system`, and root-only configuration at
`/etc/harbor-monitor/config.json` (0600 in a 0700 directory). Configuration fields:

| Field | Value |
| --- | --- |
| `kube_ca` | PEM CA for the core API at `https://127.0.0.1:6443` |
| `kube_token` | Dedicated read-only service account token |
| `kube_token_expires` | Actual token expiration in ISO 8601 |
| `ovh_certificate_expires` | Current OVH access certificate expiration in ISO 8601 |
| `critical_key` | Critical alert source event integration key |
| `warning_key` | Warning alert source event integration key |
| `heartbeat_url` | Secret ilert heartbeat ping URL |

The systemd service runs as a dynamic unprivileged user, using `LoadCredential`
to read configuration. Reload systemd and enable `harbor-monitor.timer`. Confirm
the service reports healthy and the ilert heartbeat is HEALTHY after the first
ping. Configure GitHub secret `ILERT_EXTERNAL_KEY` with the external source's event
key. Dispatch the external workflow once and inspect its result.

Rotate the service account token and update its expiry before the warning deadline.
Update the OVH expiry whenever that certificate is rotated. To revoke the monitor's
Kubernetes access immediately, delete its service account; rotation of event keys
and heartbeat URL is separate. Configuration files must never enter Git.

## Notification and failure testing

Configure high priority SMS plus email and low priority email in ilert. Phone
verification and confirmed receipt are required before relying on SMS. A role
address should receive backup email independently of the production server.
Push notifications require a registered mobile app. Keep SMS usage within the
account quota and confirm entitlements after the trial expires.

Run `python3 -m unittest discover -s deploy/monitoring -p 'test_*.py'` locally.
For delivery acceptance, send a clearly labelled synthetic alert, inspect ilert's
notification delivery log, confirm receipt, and resolve it. For a missing-heartbeat
test, stop only the monitoring timer, allow the heartbeat deadline to expire,
then restart the timer and verify automatic recovery. Do not interrupt OpenBao
or auth to test notifications. Coordinate this intentional alert with the operator.
Do not mark notification delivery verified solely because the events API accepted
the event.
