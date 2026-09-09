# OpenBao Transit and OVH auto-unseal

OpenBao runs as a single TLS-only Raft pod in the isolated Harbor core cluster.
It encrypts stored signing keys with Transit. Harbor unwraps a signing key at
startup or rotation and signs locally; ordinary signing does not contact OVH.
The OVH KMS wraps OpenBao's storage root and is needed for auto-unseal after a
restart. It does not prevent a compromised running Harbor process from using
its authorized signing material.

`values.yaml` contains the production OVH seal configuration, pinned plugin
checksum, credential mount, readiness probe, and network egress rules. Runtime
certificate/private-key values are held only in the `openbao-ovh-client`
Secret. The Git configuration must match production; no live Argo values
patch is needed after adopting this version.

## Installation prerequisites

The OVH service key must exist with encrypt/decrypt permissions for the runtime
identity. Production currently uses the US Vint Hill endpoint and an
unexportable AES-256 key. The access certificate must be valid and permitted
by OVH IAM. Keep key administration separate from this runtime identity.

Before startup, provision the checksum-verified plugin release on the data PVC:
`/openbao/data/plugins/openbao-plugin-kms-ovhcloud`, owned by the OpenBao user,
mode 0750. The required binary is v0.0.1, SHA-256
`653ed969ae963caa3622c4505be401756a91c8cd2145ac83b83249648b60f76c`.
The server verifies the configured checksum. A replacement PVC needs this
binary restored separately; the chart does not download executables at boot.

Apply `application.yaml` only to Harbor core. Supply the OVH mTLS Secret
through a protected operator session, never through Git, command arguments,
or chat. For a new, uninitialized OVH-sealed instance, run `bootstrap.sh` with
`OPENBAO_INIT_OUTPUT` set to an absolute path on encrypted operator storage.
The script creates five recovery shares with a threshold of three, then waits
for automatic unseal. It refuses other seal types and never attempts manual
unseal. Do not initialize or change the seal of an existing cluster with this
script: seal migration requires its own reviewed procedure.

Distribute recovery shares among separate custodians. They authorize recovery
operations; they cannot decrypt this cluster without OVH. Retain an initial
root token only until durable operator authentication and recovery access are
established, then revoke it. Never store root/recovery credentials in Kubernetes.

## Runtime controls

Harbor hot authenticates using its projected Kubernetes identity and receives
a short-lived OpenBao token. Its policy permits only encrypt/decrypt on the
non-exportable Transit key `harbor-eu`. Public internal CA material is copied
to Harbor; the OpenBao server private key stays in its namespace.

Readiness fails while sealed. Liveness permits a sealed response so an external
KMS outage does not cause a restart loop. Raft and audit data use separate
retained PVCs. This single-host deployment has no host-level availability
redundancy, and a compromised host can access an already-unsealed process.

NetworkPolicy restricts ingress to authorized workloads and node probes. OVH
HTTPS egress is currently pinned to `147.135.24.44/32`; reconcile the allowlist
if `us-east-vin.okms.ovh.us` changes its addresses. Monitor DNS changes, access
certificate expiration, and sealed state before relying on unattended reboots.

## Restart and recovery

A healthy restart automatically unseals through OVH. If it remains sealed,
check OVH connectivity, IAM permissions, certificate validity, plugin checksum,
and logs. Do not feed recovery shares to `operator unseal` or revert the Git
configuration to Shamir. An OVH outage can block restart recovery; there is
currently no independent offline key backup or tested recovery shim.

Encrypted Raft snapshot restoration needs the matching OVH key, valid access,
plugin binary and TLS/PKI material. Backups and an offline recovery shim were
explicitly deferred by the owner; this configuration does not close those gates.
OpenBao upgrades use OnDelete: review the release, sync the pinned configuration,
then restart deliberately. A downgrade needs a compatible recovery procedure.
