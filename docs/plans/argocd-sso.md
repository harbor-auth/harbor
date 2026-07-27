# Plan — ArgoCD SSO via Dex + GitHub OAuth (`argocd-sso`)

> **Status:** draft · **Tier:** T2.2 (infra-hardening) · **Target:** ArgoCD in `argocd`
> namespace on `51.89.98.90` · **Parent doc:** [`infra-hardening.md`](infra-hardening.md#t22--argocd-sso-replace-admin-account)

## 1. Problem statement

ArgoCD is the cluster's deploy plane: whoever authenticates to it can `kubectl apply`
anything, effectively cluster-admin. Today access is a **single shared `admin` password**
(rotated 2026-07-24, initial secret deleted — T1.3), which means:

- No per-person identity or attribution in ArgoCD's audit trail — every action is "admin".
- No offboarding story — revoking one person means rotating the shared password for all.
- No MFA — GitHub org access already enforces 2FA; the ArgoCD password bypasses that.
- Password sits in a Secret (`argocd-secret`) as the sole gate to the deploy plane.

The fix: gate ArgoCD behind GitHub OAuth via ArgoCD's embedded **Dex**, scoped to the
`harbor-auth` GitHub org, with RBAC that defaults everyone to read-only and grants deploy
rights only to the `harbor-auth:ops` team. This mirrors how Harbor itself thinks about
authn (identity provider) vs authz (policy) — dogfooding our own architecture.

## 2. Approach

### 2.1 Deliverables (in-repo, GitOps-managed)

```
deploy/argocd/
  argocd-cm-patch.yaml        # url + dex.config (GitHub connector, harbor-auth org)
  argocd-rbac-cm-patch.yaml   # policy.default readonly; ops team → role:ops
  kustomization.yaml          # strategic-merge patches over the stock ConfigMaps
  README.md                   # GitHub OAuth app setup + secret provisioning runbook
```

Patches (not full ConfigMap replacements) so we never clobber other ArgoCD settings, and
so ArgoCD's own self-management (if enabled later) diffs cleanly.

### 2.2 `argocd-cm` patch

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd
data:
  url: https://argocd.internal.harborauth.com
  admin.enabled: "false"          # step 2 — only after SSO verified working
  dex.config: |
    connectors:
    - type: github
      id: github
      name: GitHub
      config:
        clientID: <github-oauth-app-client-id>
        clientSecret: $dex.github.clientSecret
        orgs:
        - name: harbor-auth
        teamNameField: slug
        useLoginAsID: false
```

Notes:
- `$dex.github.clientSecret` dereferences a key in the `argocd-secret` Secret — the
  OAuth client secret is **never committed**. Provisioning it is a documented operator
  step (`kubectl -n argocd patch secret argocd-secret …`); long-term it moves to ESO
  (see `kms-credentials-rotation` plan).
- Listing `orgs: [harbor-auth]` restricts login to org members; Dex emits
  `harbor-auth:<team-slug>` groups for RBAC. `teamNameField: slug` guarantees stable
  team identifiers (`ops`, not display names with spaces).
- `admin.enabled: "false"` ships **commented/staged** in the patch and is flipped only
  after SSO login + RBAC are verified — never lock yourself out in one commit.

### 2.3 `argocd-rbac-cm` patch

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-rbac-cm
  namespace: argocd
data:
  policy.default: role:readonly
  scopes: "[groups]"
  policy.csv: |
    p, role:ops, applications, *, */*, allow
    p, role:ops, clusters, get, *, allow
    p, role:ops, repositories, *, *, allow
    p, role:ops, projects, get, *, allow
    p, role:ops, exec, create, */*, deny
    g, harbor-auth:ops, role:ops
```

Key RBAC decisions:
- **`policy.default: role:readonly`** — every authenticated org member can *see* app
  state (useful for debugging) but cannot sync, delete, or change anything.
- **`harbor-auth:ops` → `role:ops`** — deploy rights (sync, rollback, app CRUD) come
  from GitHub team membership; onboarding/offboarding is a GitHub team edit, no cluster
  access needed.
- **`exec` denied even for ops** — `argocd app exec` (pod shell) is a separate,
  bigger hammer; keep it off until a concrete need appears.
- `scopes: "[groups]"` makes the `g,` lines match Dex's group claims.

### 2.4 GitHub OAuth app (operator prerequisite, documented in README)

1. Create OAuth App under the `harbor-auth` **org** (not a personal account):
   - Homepage: `https://argocd.internal.harborauth.com`
   - Callback: `https://argocd.internal.harborauth.com/api/dex/callback`
2. If the org has third-party app restrictions, approve the app for the org (Dex needs
   `read:org` to resolve team membership).
3. Store client ID in `argocd-cm` (public, committable) and client secret in
   `argocd-secret` under key `dex.github.clientSecret` (operator step).

### 2.5 Rollout order (lockout-safe)

1. Commit + sync ConfigMap patches with `admin.enabled` still `"true"`.
2. Restart `argocd-dex-server` + `argocd-server` (ArgoCD picks up cm changes on restart).
3. Verify GitHub login as an ops-team member → can sync; as a non-ops member → readonly.
4. Only then flip `admin.enabled: "false"` in a follow-up commit.
5. Break-glass: admin can be re-enabled via direct `kubectl edit cm argocd-cm` on the
   node (SSH access is the recovery root of trust) — documented in README.

## 3. Implementation steps

1. Create `deploy/argocd/` with both patches, kustomization, README runbook (OAuth app
   creation, secret provisioning, restart, verification, break-glass).
2. Wire into ArgoCD app-of-apps / standalone Application so ArgoCD manages its own config.
3. Update `infra-hardening.md` T2.2 row on completion (anti-drift rule).

## 4. Validation

- `kubectl apply --dry-run=client -k deploy/argocd/` clean; YAML schema-valid.
- Login matrix verified: ops member → sync allowed; org member (non-ops) → readonly,
  sync denied with RBAC error; non-org GitHub user → login rejected by Dex.
- `argocd account can-i sync applications '*'` as each persona matches the matrix.
- ArgoCD audit log shows the GitHub username (not `admin`) on a test sync.
- After flip: `admin` login rejected; `argocd-initial-admin-secret` still absent.
- Repo checks: `go build ./... && go vet ./... && go test ./... && make agent-check`
  green (no Go changes expected; must stay green).
