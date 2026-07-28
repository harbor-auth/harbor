---
slug: falco-runtime-detection-752575e3
plan: docs/plans/falco-runtime-detection.md
---

# Tasks: Falco eBPF Runtime Threat Detection (T3.3)

## Prerequisites

- [ ] Kubernetes cluster with Linux 5.8+ nodes (modern eBPF / CO-RE requirement)
- [ ] RKE2 with containerd socket at `/run/k3s/containerd/containerd.sock`
- [ ] Kyverno `disallow-privilege-escalation` ClusterPolicy excludes `falco` namespace
- [ ] Helm 3.x available (`helm version`)

## Implementation

- [x] `deploy/falco/rules/harbor_rules.yaml` — 5 Harbor custom Falco rules:
  - `Harbor Shell Spawned` (CRITICAL)
  - `Harbor Privileged Exec` (CRITICAL)
  - `Harbor Unexpected Outbound` (WARNING)
  - `Harbor Sensitive File Read` (WARNING)
  - `Harbor Secret Mount Access by Foreign Process` (CRITICAL)
- [x] `deploy/falco/values-falco.yaml` — Helm values:
  - `driver.kind: modern_ebpf` (CO-RE)
  - RKE2 containerd socket `/run/k3s/containerd/containerd.sock`
  - Resource caps (cpu 100m/500m, memory 128Mi/512Mi)
  - `collectors.kubernetes: true` for k8s metadata enrichment
  - `falco.json_output: true` and `falco.priority: notice`
  - `customRules.harbor_rules.yaml` wired inline
- [x] `deploy/falco/falcosidekick-values.yaml` — phase-2 alert routing stub (fully commented)
- [x] `deploy/falco/namespace.yaml` — falco Namespace with PSA privileged labels
- [x] `deploy/falco/kustomization.yaml` — kustomize entrypoint referencing namespace.yaml
- [x] `deploy/falco/README.md` — install runbook, smoke tests, tuning loop, per-rule triage notes, rollback

## Validation

- [x] `helm lint falcosecurity/falco -f deploy/falco/values-falco.yaml` — 0 chart(s) failed
- [x] `helm template falco falcosecurity/falco -n falco -f deploy/falco/values-falco.yaml` — renders cleanly
- [x] `kubectl kustomize deploy/falco/` — renders without error
- [x] `go build ./... && go vet ./...` — exit 0 (no Go changes)
- [x] `go test ./...` — all packages pass
- [x] `openspec validate falco-runtime-detection-752575e3 --strict`
