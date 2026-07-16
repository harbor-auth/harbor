<!--
SPDX-FileCopyrightText: 2026 Harbor Authors
SPDX-License-Identifier: AGPL-3.0-only
-->

# Harbor Helm chart

A Helm packaging of the reference Kubernetes manifests in [`../k8s/`](../k8s/).
Same two workloads, same security posture — parameterized for reuse across
environments.

- **`harbor-hot`** — stateless, internet-facing OIDC hot path
  (`/authorize`, `/token`, `/jwks`, discovery). HPA-scaled, zone-spread.
- **`harbor-mgmt`** — cluster-internal cold path (passkey ceremonies, user
  enrollment, dashboard/BFF). No Ingress; locked down by NetworkPolicy.

## Layout

```
deploy/helm/
  Chart.yaml            # chart metadata
  values.yaml           # all tunables (image, replicas, secrets, ingress, …)
  templates/
    _helpers.tpl        # name/label/image/secret-name helpers
    NOTES.txt           # post-install guidance + SCAFFOLD reminders
    namespace.yaml      # (namespace.create) PSS-restricted namespace
    serviceaccounts.yaml# (serviceAccount.create) hot + mgmt SAs, no token automount
    configmap-hot.yaml  # PORT, ISSUER
    configmap-mgmt.yaml # PORT, WEBAUTHN_RP_*
    secret-hot.yaml     # (unless hot.secrets.existingSecret) DATABASE_URL/REDIS_URL/KEK_SECRET
    secret-mgmt.yaml    # (unless mgmt.secrets.existingSecret) DATABASE_URL/HARBOR_KEK_SECRET
    deployment-hot.yaml # 3-replica floor, /healthz probes, preStop drain, hardened securityContext
    deployment-mgmt.yaml# cold path, no REDIS_URL
    service-hot.yaml    # ClusterIP 80 -> 8080
    service-mgmt.yaml   # ClusterIP 80 -> 8081 (internal)
    ingress.yaml        # (ingress.enabled) TLS, harbor-hot only
    hpa-hot.yaml        # (hot.hpa.enabled) 3->20 on CPU/mem
    pdb-hot.yaml        # (hot.pdb.enabled) minAvailable 2
    pdb-mgmt.yaml       # (mgmt.pdb.enabled) minAvailable 1
    networkpolicy-hot.yaml  # (hot.networkPolicy.enabled) ingress from controller ns; egress redis/pg/dns
    networkpolicy-mgmt.yaml # (mgmt.networkPolicy.enabled) ingress same-ns; egress pg/dns
```

## Install

```sh
# Render only (review before applying):
helm template harbor deploy/helm/ -n harbor

# Install (creates the namespace):
helm install harbor deploy/helm/ -n harbor --create-namespace \
  --set hot.secrets.databaseUrl='postgres://…' \
  --set hot.secrets.redisUrl='redis://…' \
  --set hot.secrets.kekSecret="$(openssl rand -hex 32)" \
  --set mgmt.secrets.databaseUrl='postgres://…' \
  --set mgmt.secrets.kekSecret="$(openssl rand -hex 32)" \
  --set hot.issuer=https://auth.your-domain.com \
  --set ingress.host=auth.your-domain.com
```

If the namespace already exists, set `--set namespace.create=false`.

## Production checklist (SCAFFOLD)

The defaults render a working topology but are **not** production-ready as-is.
Before a real deployment:

1. **Pin images** — set `hot.image.digest` / `mgmt.image.digest` to immutable
   `@sha256:…` digests (or override `global.image.tag`). `latest` defeats
   rollbacks.
2. **Externalize secrets** — set `hot.secrets.existingSecret` /
   `mgmt.secrets.existingSecret` to Secrets provisioned by a secrets manager
   (Vault / External Secrets Operator) rather than passing values through Helm.
3. **Provision TLS** — the Ingress needs `ingress.tlsSecretName` to exist
   (e.g. via cert-manager).
4. **Align issuer & host** — `hot.issuer` must equal `https://` + `ingress.host`.
5. **mgmt replicas** — keep `mgmt.replicaCount: 1` until the WebAuthn ceremony
   store is DB-backed (in-memory state does not survive restarts or cross-pod
   routing). See `docs/plans/user-enrollment.md`.
6. **Redis for multi-replica hot** — `hot.secrets.redisUrl` is REQUIRED whenever
   `hot.replicaCount > 1`; without it cross-replica `/token` exchanges fail.

`helm template … | grep -i scaffold` surfaces the inline reminders, and the
post-install `NOTES.txt` re-checks the most dangerous of these against your
supplied values.
