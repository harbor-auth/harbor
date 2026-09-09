# Production ingress

Both K3s clusters use Traefik 3.7.12, chart 41.5.0, with a pinned amd64 image.
The Helm release, namespace and IngressClass retain the name `ingress-nginx`
so existing application routes and cert-manager HTTP-01 solvers keep working.
The controller implementation is Traefik's Kubernetes Ingress NGINX provider.

Apply `core.yaml` only to Harbor core and `cloud.yaml` only to Harbor Cloud.
These are K3s HelmChart resources, retained in the cluster across reboots.
They replace the old HelmChart with the same name. The compatibility provider
watches only its application namespace. Cluster RBAC covers discovery;
Secret reads are granted only in that application namespace. The API dashboard,
telemetry, and version-check requests are disabled.

## Host routing

The process runs as UID 65532 with a read-only filesystem, all capabilities
dropped, and privilege escalation disabled. It uses host networking because
the public IPv6 addresses route directly to these single-stack K3s hosts.
It listens on unprivileged ports 18081/18444. Host nftables redirects incoming
80/443 to those ports. The input chain admits only Cloudflare IPv6 sources
for translated web traffic; direct access to the high ports is not admitted.
Private core IPv4 routing remains available for the existing integration.

Install the corresponding `*-firewall.nft` as
`/etc/harbor-integration-firewall.nft`, validate with `nft --check -f`, then
apply with `nft -f`. Never flush the complete ruleset on a running K3s node.
Install `firewall-ordering.conf` under
`/etc/systemd/system/harbor-integration-firewall.service.d/ordering.conf`
and reload systemd. This orders the rules after nftables startup and before
K3s. The existing firewall service must remain enabled.

Cloudflare ranges were verified against https://www.cloudflare.com/ips-v6
on 2026-09-08. Review range changes and update both files together. The firewall
is a Cloudflare source allowlist; it does not authenticate a particular zone.

## Deployment and verification

Keep an SSH session through the hypervisor and arm a timed rollback before
changing either host routing or the HelmChart. Validate a canary controller
on separate high ports first. Forward traffic to that canary during the Helm
replacement, then switch atomically to the final listener when it is Ready.
Restore the old controller before removing the canary routing on rollback.

Verify public health, discovery/JWKS, every cloud hostname, HTTP-to-HTTPS
redirects, and case-insensitive denial of core `/admin` and billing/bridge
`/internal` paths. Issue a separate staging ACME certificate without changing
the production TLS Secret to exercise the HTTP-01 renewal path. Confirm a
non-Cloudflare source cannot reach either public origin directly. Remove
canary resources and staging certificates after successful validation.

The first direct-low-port cutover failed because NET_BIND_SERVICE alone did
not allow this image to bind privileged ports with host networking. Production
uses the unprivileged listener arrangement above; do not reintroduce a root
runtime or privilege escalation to work around that failure.
