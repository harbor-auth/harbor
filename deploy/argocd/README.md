# Harbor GitOps deployment (ArgoCD)

This directory holds the GitOps configuration that drives the running Harbor
deployment on the dedicated `harbor-core` K3s cluster. Git is the source of
truth: a push to `main`
deploys itself.

## Contents

| File | Purpose |
|------|---------|
| `application.yaml` | ArgoCD `Application` — points at `deploy/helm` with `values-prod.yaml`, auto-syncs with prune + self-heal. |
| `values-prod.yaml` | Production Helm overrides (domain, single-node replicas, existing secrets). `global.image.tag` is **managed by CI** — do not edit it by hand. |
| `argocd-cm-patch.yaml` | Strategic-merge patch adding Dex GitHub OAuth connector to `argocd-cm`. |
| `argocd-rbac-cm-patch.yaml` | Strategic-merge patch adding RBAC policy (`policy.default: role:readonly`, `harbor-auth:ops` → deploy rights). |
| `dex-secret-template.yaml` | SealedSecret template for the GitHub OAuth client secret. **Operator must run kubeseal before applying.** |
| `kustomization.yaml` | Kustomize overlay wiring the two patches and the SealedSecret together. |

---

## CI/CD flow (Harbor app)

```
git push to main (Go / Dockerfile change)
    └─▶ .github/workflows/publish.yml
          ├─ builds harbor-hot + harbor-mgmt images
          ├─ pushes ghcr.io/harbor-auth/harbor/<svc>:<sha> and :latest
          └─ pins global.image.tag → <sha> in values-prod.yaml, commits [skip ci]
              └─▶ ArgoCD (Application `harbor`) sees the git change
                    └─ runs `helm upgrade` (deploy/helm + values-prod.yaml)
                        └─▶ K3s rolls out the new images
```

Images are pinned to the **immutable commit SHA** (not `:latest`) in
`values-prod.yaml`, so every deploy is reproducible and rollbacks are just a
revert of the pinning commit.

---

## ArgoCD SSO setup (Dex + GitHub OAuth)

This section documents the one-time operator steps needed to enable GitHub OAuth
SSO for the ArgoCD UI. After this is in place, the shared admin password is no
longer needed.

### Prerequisites

#### 1. DNS — `argocd.internal.harborauth.com`

The ArgoCD ingress must be reachable at `https://argocd.internal.harborauth.com`.
Verify with:

```bash
curl -sk https://argocd.internal.harborauth.com/healthz
# Should return: ok
```

Create the `AAAA` record at the Harbor guest IPv6
(`2a01:4f8:140:4423:1::10`). Do **not** point an `A` record at the hypervisor:
one shared IPv4 cannot map TCP/80 and TCP/443 independently to both guests.
IPv4 support requires a second routed address or a deliberately managed edge
proxy. cert-manager will provision a TLS certificate when the configured issuer
is available.

#### 2. Sealed Secrets controller

The SealedSecret for the OAuth client secret requires the Bitnami Sealed Secrets
controller:

```bash
# Check if already installed:
kubectl get deployment sealed-secrets-controller -n kube-system

# If not installed:
helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets
helm repo update
helm install sealed-secrets sealed-secrets/sealed-secrets \
  -n kube-system \
  --set fullnameOverride=sealed-secrets-controller
```

### Step 1 — Create the GitHub OAuth App

1. Go to `https://github.com/organizations/harbor-auth/settings/applications` (org admin required).
2. Click **New OAuth App** and fill in:
   - **Application name:** `Harbor ArgoCD`
   - **Homepage URL:** `https://argocd.internal.harborauth.com`
   - **Authorization callback URL:** `https://argocd.internal.harborauth.com/api/dex/callback`
3. Click **Register application**.
4. Note the **Client ID** (public — add it to `argocd-cm-patch.yaml` under `clientID`).
5. Click **Generate a new client secret** and copy the value immediately (shown once).

> **Org restrictions:** If the `harbor-auth` org has third-party OAuth app restrictions
> enabled, a GitHub org admin must approve the OAuth app at
> `https://github.com/organizations/harbor-auth/settings/oauth_application_policy`
> after creation. Dex needs `read:org` scope to resolve team membership.

### Step 2 — Update the client ID in the patch

Edit `argocd-cm-patch.yaml` and replace `<github-oauth-app-client-id>` with the
real Client ID from step 1. This value is public and safe to commit.

```bash
# Example:
sed -i 's/<github-oauth-app-client-id>/Ov23li...<your-id>/' \
  deploy/argocd/argocd-cm-patch.yaml
git add deploy/argocd/argocd-cm-patch.yaml
git commit -m "chore(argocd): set GitHub OAuth client ID"
git push
```

### Step 3 — Seal the client secret

```bash
# Fetch the controller's public key:
kubeseal --fetch-cert \
  --controller-namespace kube-system \
  --controller-name sealed-secrets-controller \
  > /tmp/pub-sealed-secrets.pem

# Seal the secret (replace <CLIENT_SECRET> with the value from step 1):
SEALED=$(echo -n '<CLIENT_SECRET>' | kubeseal \
  --raw \
  --from-file=/dev/stdin \
  --namespace argocd \
  --name argocd-secret \
  --scope strict \
  --cert /tmp/pub-sealed-secrets.pem)

# Patch the template:
sed -i "s|PLACEHOLDER_REPLACE_ME_run_kubeseal_command_above|${SEALED}|" \
  deploy/argocd/dex-secret-template.yaml

git add deploy/argocd/dex-secret-template.yaml
git commit -m "chore(argocd): seal GitHub OAuth client secret"
git push
```

> **Security:** The sealed ciphertext is safe to commit — only this cluster's
> controller private key can decrypt it. The raw client secret must never be committed.

#### Alternative — imperative secret injection (no Sealed Secrets)

If Sealed Secrets is not available, inject the secret directly and skip committing
`dex-secret-template.yaml` (remove it from `kustomization.yaml` resources):

```bash
kubectl -n argocd patch secret argocd-secret \
  --type='json' \
  -p='[{"op":"add","path":"/data/dex.github.clientSecret",
        "value":"'"$(echo -n '<CLIENT_SECRET>' | base64 -w0)"'"}]'
```

### Step 4 — Apply the SSO overlay

```bash
# Dry-run first to catch any YAML errors:
kubectl apply --dry-run=client -k deploy/argocd/

# Apply:
kubectl apply -k deploy/argocd/

# Restart ArgoCD to pick up the ConfigMap changes:
kubectl rollout restart deployment argocd-dex-server argocd-server -n argocd
kubectl rollout status deployment argocd-dex-server argocd-server -n argocd
```

ArgoCD will also sync this automatically on the next reconcile cycle if the ArgoCD
Application watches the `deploy/argocd/` directory.

---

## Verification matrix

After applying, test each persona **before** disabling the admin account:

| Persona | Expected behaviour |
|---|---|
| **ops-team member** (`harbor-auth:ops`) | Can log in via GitHub. Can sync, rollback, and manage applications. |
| **org member (not ops)** (`harbor-auth`, any other team) | Can log in via GitHub. Read-only: can view apps and logs, cannot sync or delete. |
| **non-org GitHub user** | Login rejected by Dex — GitHub OAuth returns no org membership, Dex denies the token. |

```bash
# After logging in as an ops-team member via the UI, also verify via CLI:
argocd login argocd.internal.harborauth.com --sso
argocd account can-i sync applications '*'    # should return: yes
argocd account can-i delete applications '*'  # should return: yes

# As a non-ops org member:
argocd account can-i sync applications '*'    # should return: no
```

Confirm the ArgoCD audit log records the **GitHub username** (not `admin`) on a
test sync:

```bash
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-server --tail=50 | \
  grep -i audit
```

---

## Step 5 — Disable the admin account (post-verification)

Only after confirming SSO works for all three personas above:

```bash
# Edit the patch to uncomment admin.enabled: "false":
sed -i 's/# admin.enabled: "false"/admin.enabled: "false"/' \
  deploy/argocd/argocd-cm-patch.yaml
git add deploy/argocd/argocd-cm-patch.yaml
git commit -m "chore(argocd): disable admin account now SSO is verified"
git push

# Apply:
kubectl apply -k deploy/argocd/
kubectl rollout restart deployment argocd-server -n argocd
```

Verify admin login is rejected:

```bash
argocd login argocd.internal.harborauth.com --username admin --password <old-pw>
# Should fail: rpc error: code = Unauthenticated ... user "admin" is disabled
```

---

## Rollback procedure

### Rollback SSO (revert ConfigMap patches)

If SSO is broken and you need to revert quickly:

```bash
# Option A — kubectl (immediate, does not wait for ArgoCD sync):
kubectl -n argocd edit cm argocd-cm
# Remove or comment out the dex.config block and the url field.

kubectl -n argocd edit cm argocd-rbac-cm
# Remove policy.default, scopes, and policy.csv fields added by the patch.

kubectl rollout restart deployment argocd-dex-server argocd-server -n argocd

# Option B — Git revert (ArgoCD self-heals within ~3 minutes):
git revert HEAD~<n>  # revert the SSO commits
git push
```

### Remove the SealedSecret

```bash
kubectl delete sealedsecret argocd-secret -n argocd
# The underlying Secret key is NOT automatically removed. Clean up manually:
kubectl -n argocd patch secret argocd-secret \
  --type='json' \
  -p='[{"op":"remove","path":"/data/dex.github.clientSecret"}]'
```

---

## Break-glass — locked out of ArgoCD UI

If the admin account is disabled and SSO is broken (e.g. GitHub is down or the
OAuth app is misconfigured):

```bash
# SSH to the Harbor guest through the hardened hypervisor account:
ssh -J harborops@78.47.238.62 harborops@10.77.1.10

# Re-enable the admin account directly:
sudo k3s kubectl -n argocd patch cm argocd-cm \
  --type='json' \
  -p='[{"op":"replace","path":"/data/admin.enabled","value":"true"}]'

sudo k3s kubectl rollout restart deployment argocd-server -n argocd

# Retrieve the current admin password hash from argocd-secret:
sudo k3s kubectl -n argocd get secret argocd-secret \
  -o jsonpath='{.data.admin\.password}' | base64 -d
# This is the bcrypt hash. If you have lost the plaintext, set a new one:
NEW_PASSWORD_HASH=$(htpasswd -bnBC 10 "" "<new-password>" | tr -d ':\n')
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
kubectl -n argocd patch secret argocd-secret \
  --type='json' \
  -p="[{\"op\":\"replace\",\"path\":\"/data/admin.password\",\"value\":\"$(echo -n "${NEW_PASSWORD_HASH}" | base64 -w0)\"},
        {\"op\":\"replace\",\"path\":\"/data/admin.passwordMtime\",\"value\":\"$(echo -n "${NOW}" | base64 -w0)\"}]"
kubectl rollout restart deployment argocd-server -n argocd
```

After restoring access, fix the SSO configuration and re-disable the admin account
following the steps above.

---

## One-time bootstrap (initial ArgoCD install)

Harbor is deployed by **three** Applications, not one. Registering only
`application.yaml` leaves PostgreSQL/Redis/PKI and the OpenBao Transit KMS
unmanaged — which is how this cluster previously drifted from git.

```bash
# 1. Install ArgoCD:
kubectl create namespace argocd
kubectl apply -n argocd \
  -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# 2. Register all three Applications (after this file is on main).
#    `harbor-auth/harbor` is a public repository, so no ArgoCD repository
#    credential is required for these sources.
kubectl apply -f deploy/argocd/platform-application.yaml  # postgres, redis, PKI (incl. the harbor-public Certificate)
kubectl apply -f deploy/openbao/application.yaml                      # OpenBao Transit KMS (see deploy/openbao/README.md — needs a manual unseal after install)
kubectl apply -f deploy/argocd/application.yaml                       # the Harbor chart itself
```

After that, everything is automatic — merges to `main` deploy without any manual
`kubectl`/`helm` step.

### Adopting a cluster that already has hand-applied resources

Both Applications that carry `prune: true` (`harbor`, `openbao`) will delete
anything in their destination that is not in git. When adopting an existing
cluster, register each Application with its `syncPolicy.automated` block
stripped, inspect `argocd app diff <name>`, sync manually, and only then apply
the pristine manifest to switch auto-sync on:

```bash
yq 'del(.spec.syncPolicy.automated)' deploy/argocd/application.yaml | kubectl apply -n argocd -f -
argocd app diff harbor          # gate: no unexpected deletions, no immutable-field changes
argocd app sync harbor
kubectl apply -f deploy/argocd/application.yaml   # restore automated sync
```

### Preflight before the first sync of the `harbor` Application

`values-prod.yaml` sets `mgmt.cloudIntegration.enabled: true`, and `harbor-mgmt`
**refuses to boot** unless `CLOUD_SERVICE_AUTH_PUBLIC_KEY` and
`MGMT_HOT_PROXY_TOKEN` are present in the out-of-band `harbor-mgmt-secrets`
Secret. Verify both keys exist *before* syncing, or the rollout crash-loops:

```bash
kubectl get secret harbor-mgmt-secrets -n harbor -o go-template='{{range $k,$v := .data}}{{$k}}{{"\n"}}{{end}}'
```

Note that this cluster's sealed-secrets controller is installed with
`fullnameOverride=sealed-secrets-controller`, so resealing here needs
`kubeseal --controller-name sealed-secrets-controller`. The Harbor Cloud cluster
uses the name `sealed-secrets` — the two are deliberately independent.

---

## Changing the domain

Edit these values **together** in `values-prod.yaml` (they must all agree, or
OIDC discovery / WebAuthn origin checks will fail closed) and commit:

- `ingress.host`
- `hot.issuer`
- `mgmt.webauthn.rpId`, `mgmt.webauthn.rpName`, `mgmt.webauthn.rpOrigin`

Also update `argocd-cm-patch.yaml` `url:` to the new ArgoCD hostname, and recreate
the GitHub OAuth App callback URL.
