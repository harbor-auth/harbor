# Tasks: Falco eBPF runtime threat detection (T3.3)

## Prerequisites

- [ ] **Pure infrastructure change** — no Go code, no DB migration, no sqlc,
  no codegen. All deliverables are YAML files and documentation under `deploy/falco/`.
- [ ] **`docs/plans/infra-hardening.md` T3.3 context** — this change realises
  the T3.3 item from the infra-hardening roadmap. Kyverno (T2.4) is a future
  dependency; coordinate with it when deployed.

## Implementation

- [ ] `deploy/falco/rules/harbor_rules.yaml`: Define the 5 Harbor-specific
  additive Falco rules (Harbor Shell Spawned CRITICAL, Harbor Privileged Exec
  CRITICAL, Harbor Unexpected Outbound WARNING, Harbor Sensitive File Read
  WARNING, Harbor Secret Mount Access by Foreign Process CRITICAL), scoped to
  the `harbor` namespace, using additive `append: true` or `override: false`
  pattern. Validate with `falco --validate deploy/falco/rules/harbor_rules.yaml`.
- [ ] `deploy/falco/values-falco.yaml`: Helm values for the Falco chart —
  `driver.kind=modern_ebpf`, RKE2 containerd socket
  `/run/k3s/containerd/containerd.sock`, resource caps (cpu 500m / memory 512Mi
  limits, cpu 100m / memory 128Mi requests), k8s metadata collector enabled,
  JSON stdout output (`jsonOutput: true`), `priority: notice` threshold, and
  `customRules` wiring that references `harbor_rules.yaml`.
- [ ] `deploy/falco/falcosidekick-values.yaml`: Commented-out stub for phase 2
  alert routing — document the intent (PagerDuty / Slack via Falcosidekick) but
  leave all values commented. Enables phase 2 as a two-line uncomment.
- [ ] `deploy/falco/kustomization.yaml`: Kustomize entrypoint — includes the
  Falco namespace manifest (with PSA `privileged` labels), references the custom
  rules ConfigMap (if used), and documents the Kyverno
  `disallow-privilege-escalation` exclusion requirement for the `falco` namespace.
- [ ] `deploy/falco/README.md`: Install runbook (helm repo add, helm install
  with values-falco.yaml), verification smoke tests (`kubectl logs -n falco`,
  `kubectl exec ... cat /proc/1/status | grep CapEff`), per-rule triage notes
  for all 5 rules, the shadow-then-alert tuning-loop procedure, and rollback
  instructions (`helm uninstall falco -n falco`).

## Validation

- [ ] `falco --validate deploy/falco/rules/harbor_rules.yaml` exits 0
- [ ] `helm lint deploy/falco/` exits 0 (or exits with warnings only — no errors)
- [ ] `helm template falco falcosecurity/falco -f deploy/falco/values-falco.yaml | kubectl apply --dry-run=client -f -` succeeds
- [ ] `go build ./... && go vet ./... && go test ./...` (no Go changes; must stay green)
- [ ] `make agent-check` is green
- [ ] `openspec validate falco-runtime-detection-752575e3 --strict`
