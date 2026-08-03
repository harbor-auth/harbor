# In-cluster OpenBao Transit KMS

This is Harbor's interim KMS. It runs only in the isolated Harbor K3s cluster;
Harbor Cloud has no route, Kubernetes identity, policy, token, or key access.

OpenBao is configured as a one-pod Raft service because the current Harbor
cluster has one node. It is durable, TLS-only, audited, and network-isolated,
but it is **not** an independent security or availability boundary from the
Harbor cluster/physical host. Move to a managed or separately hosted KMS before
requiring host-compromise resistance or high availability.

## Security properties

- OpenBao 2.6.1 and chart 0.28.6 are pinned; the server image is digest-pinned.
- Transit key `harbor-eu` is non-exportable. `harbor-hot` can only call its
  encrypt and decrypt endpoints.
- `harbor-hot` authenticates with a 10-minute projected service-account token;
  OpenBao returns a 15-minute token. No static OpenBao token is mounted.
- End-to-end TLS is mandatory. Only the public internal CA is copied to Harbor.
- Five Shamir unseal shares are created with a threshold of three. Shares and
  the initial root token must never be stored in Kubernetes, git, or together.
- NetworkPolicy permits port 8200 only from `harbor-hot`, the OpenBao pod, and
  the Harbor node's kubelet probes. OpenBao egress is limited to DNS, the K3s
  API, and itself.
- Raft data and audit logs use separate retained PVCs.

## Install and initialize

1. Merge the deployment branch, then apply `application.yaml` to the Harbor
   ArgoCD instance. Do not apply it to Harbor Cloud.
2. Wait for cert-manager to create `openbao-server-tls` and for `openbao-0` to
   enter Running state. It will remain sealed until initialized.
3. Ensure the `harbor` namespace exists.
4. On encrypted operator storage, choose an absolute output path outside the
   repository and run:

   ```sh
   cd deploy/openbao
   OPENBAO_INIT_OUTPUT=/secure/offline/openbao-init.json ./bootstrap.sh
   ```

5. Immediately split the five unseal shares among separate custodians. Retain
   the initial root token only until a durable human/operator auth method and
   narrowly scoped recovery procedure have been established, then revoke it.

The bootstrap is fail-closed: it refuses to initialize without an absolute
protected output path and refuses to overwrite an existing init file.

## Restart / unseal

OpenBao deliberately does not auto-unseal with a key stored on the same
cluster. After the pod or node restarts, three custodians must each provide a
share:

```sh
kubectl exec -it -n openbao openbao-0 -- \
  env BAO_ADDR=https://openbao.openbao.svc:8200 BAO_CACERT=/openbao/tls/ca.crt \
  bao operator unseal
```

Do not place shares on a command line, in chat, or in shell history; enter them
at the prompt.

## Backup and recovery

Take an encrypted Raft snapshot after initialization and before every upgrade
or key-policy change. Run the snapshot command through `kubectl exec`, write it
directly to encrypted operator storage, and test restoration in an isolated
cluster. Backing up only the PVC is not enough; recovery also requires three
unseal shares and the internal TLS/PKI configuration.

OpenBao upgrades use an `OnDelete` StatefulSet strategy. Review release notes,
take and verify a snapshot, sync the new pinned chart/image, then explicitly
delete the old pod. Never attempt an in-place downgrade without restoring the
matching pre-upgrade snapshot.
