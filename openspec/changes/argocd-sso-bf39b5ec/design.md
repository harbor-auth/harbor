# Design: ArgoCD SSO with Dex + GitHub OAuth (T2.2)

## Key Decisions

### Decision 1: Use ArgoCD's built-in Dex (not an external OIDC provider)
**Chosen:** Configure the Dex instance that ships with ArgoCD rather than
pointing `oidc.config` at an external provider (including Harbor's own OIDC).
**Rationale:** ArgoCD bundles Dex specifically for this use case. Using it
avoids running an extra identity service and keeps the SSO config entirely
within the ArgoCD namespace. Harbor's OIDC is purpose-built for end-user
authentication with privacy constraints (PPID, PKCE) that are unnecessary
overhead for an internal ops tool.
**Alternatives considered:** Use Harbor as the OIDC provider for ArgoCD
(rejected — couples infra-ops access to the app's availability; PPID sub
would mismatch ArgoCD's expectations); use a separate Keycloak/Dex deployment
(rejected — more infra to maintain).

### Decision 2: GitHub OAuth scoped to harbor-auth org + ops team
**Chosen:** Dex `github` connector with `orgs: [{name: harbor-auth, teams: [ops]}]`.
**Rationale:** GitHub org membership is already the authoritative identity for
the harbor-auth project. Scoping to the `ops` team gives a fine-grained gate
that can be managed via GitHub's team UI without any ArgoCD config changes.
**Alternatives considered:** Scope to entire GitHub org (rejected — too broad;
any org member gets read access which may be acceptable but ops team membership
is a tighter gate for deploy rights); use email-based allowlist (rejected —
fragile, hard to maintain).

### Decision 3: SealedSecret (or ExternalSecret stub) for the OAuth client secret
**Chosen:** Provide a `dex-secret-template.yaml` as a SealedSecret YAML template
(with placeholder encrypted values) plus a comment block explaining how to
seal the real secret with `kubeseal`.
**Rationale:** Secrets must never be committed in plaintext. SealedSecrets
are already part of the cluster's GitOps story. The template gives the operator
a copy-paste starting point; real sealing happens once with `kubeseal` and the
result is committed.
**Alternatives considered:** ExternalSecret pulling from a vault (rejected as
  too heavy for a single secret; deferred to T3.4); plain Secret with a
`.gitignore` note (rejected — too easy to accidentally commit).

### Decision 4: Kustomize overlay (not Helm) for ArgoCD config patches
**Chosen:** `kustomization.yaml` with `patches:` pointing at
`argocd-cm-patch.yaml` and `argocd-rbac-cm-patch.yaml`, plus a `resources:`
block for the sealed secret.
**Rationale:** ArgoCD's own config (the `argocd-cm` and `argocd-rbac-cm`
ConfigMaps) lives in the `argocd` namespace under ArgoCD's own control — not
in Harbor's Helm chart. Kustomize patches are the idiomatic way to overlay
changes onto those managed resources without owning them in a Helm release.
**Alternatives considered:** Edit ArgoCD's ConfigMaps imperatively (rejected —
not GitOps; ArgoCD self-heals by reverting manual changes); add ArgoCD config
to Harbor's Helm chart (rejected — wrong namespace, wrong concern separation).

### Decision 5: RBAC — readonly default, ops team gets deploy rights
**Chosen:** `policy.default: role:readonly` in `argocd-rbac-cm`, plus an
explicit CSV row granting `harbor-auth:ops` the `role:ops` policy
(applications `*` + clusters `get`).
**Rationale:** Least-privilege default: any authenticated GitHub user in the
org gets read-only (can see app state, logs), but only the `ops` team can
trigger syncs or rollbacks. This is the minimum viable RBAC for a team where
multiple engineers need visibility but fewer need deploy rights.
**Alternatives considered:** No default policy / deny all (rejected — forces
explicit grants for every read-only user; ops overhead); readonly + a separate
admin role (future — not needed at single-team scale).

## Architecture

```
github.com (OAuth app)
        │  redirect (code)
        ▼
  ArgoCD UI  ──────────────▶  argocd-server
                                    │  OIDC flow
                                    ▼
                               dex (built-in)
                                    │  github connector
                                    ▼
                             api.github.com
                             (org+team check)
                                    │  token + groups
                                    ▼
                         argocd-rbac-cm
                         (policy.csv maps
                          harbor-auth:ops
                          → role:ops)
```

## File Map

| File | Kind | Purpose |
|---|---|---|
| `deploy/argocd/argocd-cm-patch.yaml` | ConfigMap patch | Dex connector + ArgoCD URL |
| `deploy/argocd/argocd-rbac-cm-patch.yaml` | ConfigMap patch | RBAC policy |
| `deploy/argocd/dex-secret-template.yaml` | SealedSecret template | GitHub OAuth client secret |
| `deploy/argocd/kustomization.yaml` | Kustomize overlay | Wires patches + secret |
| `deploy/argocd/README.md` | Documentation | Setup guide + rollback |
| `docs/plans/argocd-sso.md` | Plan | Feature plan-of-record |
