# Plan — Kyverno Policy-as-Code (`kyverno-policies`)

> **Status:** draft · **Tier:** T2.4 (infra-hardening) · **Target:** cluster-wide on
> `51.89.98.90` (RKE2, single-node, ArgoCD GitOps) · **Parent doc:** [`infra-hardening.md`](infra-hardening.md#t24--kyverno-policy-as-code)

## 1. Problem statement

The cluster enforces Pod Security Admission `restricted` on the `harbor` namespace, but
PSA is a **fixed, coarse profile** — it cannot express Harbor-specific standards:

- Nothing stops a `:latest` image tag from being deployed (non-reproducible rollbacks,
  silent drift between "what's running" and "what git says").
- Nothing requires CPU/memory limits — one runaway pod on a **single-node** cluster
  starves etcd, the API server, and every Harbor workload simultaneously.
- No enforcement of labeling conventions (`app.kubernetes.io/name`, `…/version`), which
  the observability and audit tooling assume.
- PSA covers only the `harbor` namespace; `argocd`, future `linkerd`/`falco`/`kyverno`
  namespaces have no guardrails at all.
- Every guardrail today is *convention*, checked by humans at review time — nothing is
  enforced at admission, so a bad `kubectl apply` or a subtly wrong ArgoCD sync lands.

Kyverno gives declarative, YAML-native admission policies (no Rego), versioned in git and
deployed by ArgoCD like everything else. It is also the prerequisite for T3.2
(Cosign `verifyImages`).

## 2. Approach

### 2.1 Deliverables (in-repo)

```
deploy/kyverno/
  values-kyverno.yaml                      # Helm values: single-replica, resource caps
  policies/
    disallow-latest-tag.yaml               # Enforce
    require-resource-limits.yaml           # Enforce
    disallow-privilege-escalation.yaml     # Enforce
    require-harbor-labels.yaml             # Audit
  kustomization.yaml
  README.md                                # install, exception process, rollback
```

### 2.2 Installation profile (single-node aware)

Helm chart `kyverno/kyverno`, pinned version, with:

- `admissionController.replicas: 1` (and single replicas for background/cleanup/reports
  controllers) — HA is meaningless on one node; 3 replicas would just triple memory.
- **Failure policy `Ignore` on the admission webhook initially** (chart default is
  fail-open for the resource webhook): on a single-node cluster a crashed Kyverno with
  `Fail` would block *all* pod admission, including Kyverno's own restart — a
  self-deadlock. Revisit `Fail` only with multi-replica on multi-node. This is the key
  availability-vs-enforcement decision; documented explicitly in README.
- Resource requests/limits set modestly (e.g. 128Mi/256Mi admission controller) —
  practicing what `require-resource-limits` preaches.
- `config.resourceFilters`: keep defaults excluding `kube-system`, and add exclusions
  for `kube-node-lease`, Kyverno's own namespace — never let policy block the
  control plane or RKE2 static pods.

### 2.3 The four priority policies

| Policy | Mode | Scope | Rule |
|---|---|---|---|
| `disallow-latest-tag` | **Enforce** | `harbor`, `argocd` (namespace selector) | Deny Pods (via controller autogen for Deployments/Jobs/CronJobs) whose containers/initContainers use no tag or `:latest`. |
| `require-resource-limits` | **Enforce** | `harbor` | Every container must set `resources.limits.cpu` and `resources.limits.memory` and requests. |
| `disallow-privilege-escalation` | **Enforce** | cluster-wide minus system namespaces | `allowPrivilegeEscalation` must be `false`; belt-and-suspenders over PSA `restricted`, but extends coverage to namespaces PSA doesn't label. |
| `require-harbor-labels` | **Audit** | `harbor` | Pods must carry `app.kubernetes.io/name` + `app.kubernetes.io/version`. Audit-only: third-party charts (postgres, redis) may not comply; we want visibility, not outages. |

Policy authoring conventions:
- `spec.validationFailureAction: Enforce` / `Audit` per table; **every Enforce policy
  ships with `background: true`** so existing non-compliant resources surface in
  PolicyReports before they block anything.
- Use Kyverno **autogen** (default) so rules written against Pods automatically cover
  Deployments/StatefulSets/DaemonSets/Jobs/CronJobs.
- Namespace scoping via `match.any[].resources.namespaces`, and explicit `exclude` for
  `kube-system`, `kyverno`, `cert-manager` where appropriate — the ingress controller
  and RKE2 components are not ours to break.
- Each policy carries `annotations: policies.kyverno.io/description` + severity for
  report tooling.

### 2.4 Rollout order (no-surprises)

1. Install Kyverno; wait ready.
2. Apply **all four policies in `Audit`** first (one commit).
3. Review `kubectl get policyreport -A` — fix any Harbor-chart violations found (e.g.
   a missing limit in `deployment-mgmt.yaml` gets fixed in the same feature).
4. Flip the three Enforce policies to `Enforce` (second commit) once reports are clean
   for Harbor-owned workloads.
5. ArgoCD app for `deploy/kyverno/` with sync-wave ordering: Kyverno install wave
   before policies wave (policies are CRs of Kyverno's CRDs).

## 3. Implementation steps

1. Write `values-kyverno.yaml` (single-replica, fail-open, resource caps, pinned).
2. Author the four ClusterPolicies per §2.3 with autogen + background scanning.
3. Fix any existing Harbor chart violations the policies would flag (notably: verify all
   chart containers pin tags and declare limits — make the repo compliant with its own law).
4. `deploy/kyverno/README.md`: install runbook, Audit→Enforce promotion steps, how to
   read PolicyReports, exception process (`PolicyException` CR, PR-reviewed only),
   rollback (`validationFailureAction: Audit` flip, or webhook deletion in emergency).
5. Wire into ArgoCD app-of-apps with sync waves.

## 4. Validation

- `kubectl apply --dry-run=client -f deploy/kyverno/policies/` clean (CRD schemas
  validated with `kubeconform -ignore-missing-schemas` fallback documented).
- `helm lint` on the Harbor chart still green after any compliance fixes.
- **Kyverno CLI offline tests**: `kyverno apply deploy/kyverno/policies/ --resource <fixture>`
  with good/bad fixture manifests committed under `deploy/kyverno/tests/` — a `:latest`
  pod is denied, a limit-less pod is denied, `allowPrivilegeEscalation: true` denied,
  unlabeled pod produces an Audit result. This runs in CI without a cluster.
- On-cluster: `kubectl run bad --image=nginx:latest -n harbor` rejected with policy
  message; `kubectl get policyreport -A` shows zero Enforce-severity violations for
  Harbor-owned workloads.
- Control-plane safety: RKE2 static pods and kube-system untouched (verify no
  policyreports created against excluded namespaces).
- Repo checks: `go build ./... && go vet ./... && go test ./... && make agent-check` green.
