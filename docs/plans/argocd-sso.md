# Plan — ArgoCD SSO via Dex + GitHub OAuth (`argocd-sso`)

> **Status:** in-progress · **Tier:** T2.2 (infra-hardening) · **Target:** ArgoCD in
> `argocd` namespace on `51.89.98.90` · **Parent doc:**
> [`infra-hardening.md`](infra-hardening.md#t22--argocd-sso-replace-admin-account)
>
> **Design refs:** [`DESIGN.md §Authentication`](../DESIGN.md) ·
> [`infra-hardening.md`](infra-hardening.md)
>
> **OpenSpec cross-link:** n/a — this is a pure infrastructure/GitOps change; no new
> API endpoints or OIDC spec obligations arise. The ArgoCD UI itself uses Dex's OIDC
> flow internally; the Harbor OIDC spec (`openspec/`) is unaffected.
>
> **Weft feature:** `feat_bf39b5ec-41b7-4f73-9f3c-b491ffed2276` (`argocd-sso`)

---

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

---

## 2. Proposed approach

### 2.1 Deliverables (in-repo, GitOps-managed)

```
deploy/argocd/
  argocd-cm-patch.yaml        # url + dex.config (GitHub connector, harbor-auth org)
  argocd-rbac-cm-patch.yaml   # policy.default readonly; ops team → role:ops
  dex-secret-template.yaml    # SealedSecret template / ExternalSecret stub
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
  # admin.enabled: "false"   # Step 2 — flip ONLY after SSO verified working
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

### 2.4 SealedSecret / ExternalSecret stub for the OAuth client secret

A `dex-secret-template.yaml` ships as a documented placeholder showing the expected
shape of the `argocd-secret` patch (or a full SealedSecret if `kubeseal` is available).
The actual sealed ciphertext is produced by the operator running the runbook; the
template is committed so the GitOps structure is complete. Long-term, this moves to
External Secrets Operator (ESO) alongside `kms-credentials-rotation`.

### 2.5 GitHub OAuth app (operator prerequisite, documented in README)

1. Create OAuth App under the `harbor-auth` **org** (not a personal account):
   - Homepage: `https://argocd.internal.harborauth.com`
   - Callback: `https://argocd.internal.harborauth.com/api/dex/callback`
2. If the org has third-party app restrictions, approve the app for the org (Dex needs
   `read:org` to resolve team membership).
3. Store client ID in `argocd-cm` (public, committable) and client secret in
   `argocd-secret` under key `dex.github.clientSecret` (operator step).

### 2.6 Rollout order (lockout-safe)

1. Commit + sync ConfigMap patches with `admin.enabled` still `"true"`.
2. Restart `argocd-dex-server` + `argocd-server` (ArgoCD picks up cm changes on restart).
3. Verify GitHub login as an ops-team member → can sync; as a non-ops member → readonly.
4. Only then flip `admin.enabled: "false"` in a follow-up commit.
5. Break-glass: admin can be re-enabled via direct `kubectl edit cm argocd-cm` on the
   node (SSH access is the recovery root of trust) — documented in README.

---

## 3. Implementation checklist

- [ ] `deploy/argocd/argocd-cm-patch.yaml` — Dex GitHub connector ConfigMap patch
- [ ] `deploy/argocd/argocd-rbac-cm-patch.yaml` — RBAC policy patch
- [ ] `deploy/argocd/dex-secret-template.yaml` — SealedSecret template for OAuth client secret
- [ ] `deploy/argocd/kustomization.yaml` — Kustomize overlay wiring both patches + secret template
- [ ] `deploy/argocd/README.md` — Runbook: GitHub OAuth app registration, DNS prereqs, secret provisioning, restart/verify steps, break-glass rollback
- [ ] Update `infra-hardening.md` T2.2 row to mark complete (anti-drift)
- [ ] `kubectl apply --dry-run=client -k deploy/argocd/` passes clean
- [ ] `go build ./... && go vet ./... && go test ./... && make agent-check` green

---

## 4. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **Lock-out during rollout** — disabling admin before SSO is verified working | Medium | High | Ship `admin.enabled: "false"` commented out; only flip in a separate follow-up commit after manual SSO verification. Break-glass via `kubectl edit cm argocd-cm` (SSH root of trust). |
| **GitHub OAuth app misconfigured** (wrong callback URL, missing `read:org` scope) | Medium | Medium | Runbook includes exact callback URL and org-restriction approval steps. Test login before flipping admin off. |
| **Team slug drift** — GitHub renames the `ops` team | Low | High | `teamNameField: slug` binds to the stable slug. Document in README that renaming the team requires a matching update to `argocd-rbac-cm`. |
| **Client secret committed accidentally** | Low | High | Secret is never in the patch file; template ships a placeholder. Operator step uses `kubectl patch secret` only. Long-term: ESO. |
| **ArgoCD self-sync loop** — ArgoCD managing its own config causes infinite reconcile | Low | Medium | Patches target `argocd-cm` / `argocd-rbac-cm` which ArgoCD syncs but does not own exclusively. Use `Server-Side Apply` merge strategy in kustomization to avoid clobber. |
| **Dex unavailable at startup** — GitHub API unreachable blocks Dex init | Low | Medium | Dex caches tokens; existing sessions survive transient GitHub outages. Add `readinessProbe` awareness in README. |

---

## 5. Definition of done

- [ ] All files in `deploy/argocd/` committed on branch `weft/argocd-sso-bf39b5ec` and pushed.
- [ ] `kubectl apply --dry-run=client -k deploy/argocd/` exits 0 (YAML schema-valid, Kustomize overlay resolves cleanly).
- [ ] `go build ./... && go vet ./... && go test ./... && make agent-check` all green (no Go changes expected; must not regress).
- [ ] README covers: GitHub OAuth app creation steps, DNS prereq (`argocd.internal.harborauth.com` resolves to cluster ingress), secret provisioning (`kubectl patch secret`), restart procedure, SSO verification matrix (ops-member / org-member / non-member), and break-glass rollback.
- [ ] `infra-hardening.md` T2.2 row updated with completion date.
- [ ] PR merged to main with CI green.
- [ ] **Post-deploy (manual, out-of-band):** operator verifies SSO login matrix on live cluster, then flips `admin.enabled: "false"` in a follow-up commit — this is **not** a blocker for PR merge.
