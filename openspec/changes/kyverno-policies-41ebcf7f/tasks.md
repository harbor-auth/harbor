# Tasks: Kyverno policy-as-code (T2.4 infra hardening)

## Prerequisites

- [ ] No Go code changes — this feature adds Kubernetes YAML under `deploy/kyverno/` only.
- [ ] No DB migration — no application schema change.
- [ ] No dependency on other in-flight features. Kyverno installs independently.
- [ ] `docs/plans/kyverno-policies.md` plan file authored (Task 1 ✅).
- [ ] The `falco` namespace exclusion is shipped from day one regardless of whether the
  Falco plan (`falco-runtime-detection`) has landed — pre-emptive correctness.

## Implementation

- [ ] `deploy/kyverno/values-kyverno.yaml`: Helm values for `kyverno/kyverno` chart —
  `admissionController.replicas: 1`, `backgroundController.replicas: 1`,
  `cleanupController.replicas: 1`, `reportsController.replicas: 1`;
  `failurePolicy: Ignore`; webhook timeout 10s; resource requests/limits for the admission
  controller (e.g. `128Mi`/`256Mi`); `config.resourceFilters` excluding `kube-system`,
  `kube-node-lease`, `kyverno`.

- [ ] `deploy/kyverno/policies/disallow-latest-tag.yaml`: ClusterPolicy —
  `validationFailureAction: Enforce`; `background: true`; namespace selector matching
  `harbor` + `argocd`; deny any container or initContainer whose image tag is `:latest`
  or absent; autogen enabled.

- [ ] `deploy/kyverno/policies/require-resource-limits.yaml`: ClusterPolicy —
  `validationFailureAction: Enforce`; `background: true`; namespace `harbor`; deny any
  container missing `resources.limits.cpu` or `resources.limits.memory`; autogen enabled.

- [ ] `deploy/kyverno/policies/disallow-privilege-escalation.yaml`: ClusterPolicy —
  `validationFailureAction: Enforce`; `background: true`; cluster-wide match; explicit
  `exclude` block for namespaces `kube-system`, `kyverno`, `cert-manager`, `falco`;
  deny any container with `allowPrivilegeEscalation: true` or where the field is absent
  (missing = default true); autogen enabled.

- [ ] `deploy/kyverno/policies/require-harbor-labels.yaml`: ClusterPolicy —
  `validationFailureAction: Audit`; `background: true`; namespace `harbor`; warn when
  `app.kubernetes.io/name` or `app.kubernetes.io/version` is missing from Pod metadata
  labels; autogen enabled.

- [ ] `deploy/kyverno/kustomization.yaml`: lists all policy files; references
  `values-kyverno.yaml`; includes ArgoCD sync-wave annotations so the Kyverno Helm chart
  installs (wave 0) before policies (wave 1).

- [ ] `deploy/kyverno/README.md`: install order (Helm install kyverno → apply policies);
  policy mode rationale (fail-open webhook, Audit-first → Enforce); how to add exceptions
  (`PolicyException` CR, PR-reviewed, never in-cluster ad-hoc); rollback procedure
  (`validationFailureAction: Audit` flip or emergency webhook deletion); cross-link to
  `docs/plans/kyverno-policies.md`.

- [ ] Verify Harbor chart manifests comply with the Enforce policies — all container
  images must pin a concrete tag (not `:latest`), all containers must declare CPU + memory
  limits; fix any violations in the same PR.

## Tests

- [ ] Offline Kyverno CLI tests (`kyverno apply … --resource <fixture>`), or committed
  fixture manifest + documented manual verification gate if kyverno CLI is not in CI:
  - `disallow-latest-tag`: fixture with `:latest` image → Enforce result (policy violation);
    fixture with pinned tag (e.g. `nginx:1.25.3`) → Pass.
  - `require-resource-limits`: fixture missing `limits.cpu` → Enforce result; fixture
    with both limits set → Pass.
  - `disallow-privilege-escalation`: fixture with `allowPrivilegeEscalation: true` →
    Enforce result; fixture with `allowPrivilegeEscalation: false` → Pass.
  - `disallow-privilege-escalation` with `falco` namespace: same privileged fixture → Pass
    (excluded namespace).
  - `require-harbor-labels`: fixture missing `app.kubernetes.io/name` → Audit result;
    fixture with both labels → Pass.
- [ ] `helm lint deploy/kyverno/` — clean with no errors or warnings.
- [ ] `kubectl apply --dry-run=client -f deploy/kyverno/policies/` — all four policies
  accepted by the dry-run API server.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...` — green (no Go changes; must stay green).
- [ ] `make agent-check` — green.
- [ ] `openspec validate kyverno-policies-41ebcf7f --strict` — clean.
