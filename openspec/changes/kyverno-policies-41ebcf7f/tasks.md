# Tasks: Kyverno policy-as-code (T2.4 infra hardening)

## Prerequisites

- [ ] No DB migration — this is a pure infrastructure change; no Go code changes.
- [ ] Kyverno Helm chart available at `https://kyverno.github.io/kyverno/`.
- [ ] Single-node RKE2 cluster at `51.89.98.90`; `kubectl` and `helm` access via
  SSH (available on the cluster node, not necessarily in CI container).
- [ ] `falco` namespace may not exist yet; the policy exclude is forward-looking.

## Implementation

- [ ] `docs/plans/kyverno-policies.md` — Harbor plan-of-record (Problem, Proposed
  approach, DESIGN alignment §infra, Target paths, Implementation checklist,
  Risks, Definition of done). Add row to `docs/README.md` Plans table.
- [ ] `openspec/changes/kyverno-policies-41ebcf7f/` — OpenSpec artifacts
  (proposal.md, design.md, tasks.md, specs/spec.md with ADDED Requirements and
  Given/When/Then scenarios). Cross-link to plan.
- [ ] `deploy/kyverno/values-kyverno.yaml` — Helm values override file:
  `replicaCount: 1`, resource requests/limits, admission webhook timeout (5 s).
- [ ] `deploy/kyverno/policies/disallow-latest-tag.yaml` — ClusterPolicy,
  `validationFailureAction: Enforce`; pattern-match `image: "*:latest"` and
  untagged images.
- [ ] `deploy/kyverno/policies/require-resource-limits.yaml` — ClusterPolicy,
  `validationFailureAction: Enforce`; all containers must have `.resources.limits`
  with CPU and memory set.
- [ ] `deploy/kyverno/policies/disallow-privilege-escalation.yaml` — ClusterPolicy,
  `validationFailureAction: Enforce`; deny `allowPrivilegeEscalation: true` or
  `securityContext.privileged: true`; exclude `falco` namespace.
- [ ] `deploy/kyverno/policies/require-harbor-labels.yaml` — ClusterPolicy,
  `validationFailureAction: Audit`; namespaceSelector scoped to `harbor`;
  require `app.kubernetes.io/name` and `app.kubernetes.io/version`.
- [ ] `deploy/kyverno/kustomization.yaml` — kustomize resource list referencing
  the four policy manifests under `policies/`.
- [ ] `deploy/kyverno/README.md` — install order, policy mode rationale, how to
  add exceptions via Kyverno `exclude`, rollback procedure.

## Tests

- [ ] YAML-validate all policy manifests (`python3 -c "import yaml,sys; yaml.safe_load(sys.stdin)" < <file>`).
- [ ] Confirm `disallow-privilege-escalation` exclude block targets `falco`
  namespace by reading the manifest.
- [ ] Confirm each policy uses exactly one `validationFailureAction` value.
- [ ] Confirm `require-harbor-labels` carries a `namespaceSelector` limiting it
  to the `harbor` namespace.

## Validation

- [ ] `go build ./... && go vet ./... && go test ./...`
- [ ] `make agent-check`
- [ ] `openspec validate kyverno-policies-41ebcf7f --strict`
- [ ] YAML syntax check on all new manifests: `python3 -c "import yaml,pathlib; [yaml.safe_load(p.read_text()) for p in pathlib.Path('deploy/kyverno').rglob('*.yaml')]"`
