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
    configmap-hot.yaml  # PORT, ISSUER, LOGIN_URL, REGION, KMS_KEY_MAP
    configmap-mgmt.yaml # PORT, REGION, WebAuthn and registration URLs
    secret-hot.yaml     # Postgres, Redis, shared user-DEK KEK, admin token
    secret-mgmt.yaml    # Postgres, Redis, shared user-DEK KEK, registration token
    deployment-hot.yaml # 3-replica floor, /healthz probes, preStop drain, hardened securityContext
    deployment-mgmt.yaml# cold path backed by PostgreSQL and Redis
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
  --set global.userDekKekSecret="$(openssl rand -hex 32)" \
  --set hot.secrets.databaseUrl='postgres://…' \
  --set hot.secrets.redisUrl='redis://…' \
  --set hot.secrets.adminApiToken="$(openssl rand -hex 32)" \
  --set mgmt.secrets.databaseUrl='postgres://…' \
  --set mgmt.secrets.redisUrl='redis://…' \
  --set mgmt.secrets.initialAccessToken="$(openssl rand -hex 32)" \
  --set hot.issuer=https://auth.your-domain.com \
  --set hot.loginURL=https://auth.your-domain.com/login \
  --set mgmt.authorizeCompleteURL=https://auth.your-domain.com/authorize/complete \
  --set mgmt.registrationBaseURL=https://auth.your-domain.com \
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
5. **Configure both durable stores** — both component Secrets must contain
   non-empty `DATABASE_URL` and `REDIS_URL`; neither binary has an in-memory
   production fallback.
6. **Share the user-DEK KEK** — set `global.userDekKekSecret` once. The chart
   projects that exact value as `HARBOR_KMS_SECRET` into both workloads so data
   wrapped by management can be unwrapped by hot. It is distinct from
   `kmsKeyMap`, which selects regional signing keys.
7. **Configure browser and registration URLs** — set `hot.loginURL`,
   `mgmt.authorizeCompleteURL`, and `mgmt.registrationBaseURL` to absolute
   public URLs, and set `mgmt.webauthn.*` for the same deployment domain.

`helm template … | grep -i scaffold` surfaces the inline reminders, and the
post-install `NOTES.txt` re-checks the most dangerous of these against your
supplied values.
