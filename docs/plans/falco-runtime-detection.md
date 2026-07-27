---
slug: falco-runtime-detection
title: "T3.3 — Falco eBPF runtime threat detection"
status: approved
design_refs: "docs/plans/infra-hardening.md#t33"
openspec: openspec/changes/falco-runtime-detection-752575e3/
---

# T3.3 — Falco eBPF runtime threat detection

> Paired OpenSpec: `openspec/changes/falco-runtime-detection-752575e3/`
> Infra hardening tier: T3.3 (from `docs/plans/infra-hardening.md`)

## Problem

Harbor's production cluster has no kernel-level visibility into runtime
behaviour. A compromised container can spawn a shell, exfiltrate secrets, open
unexpected outbound connections, or read sensitive files — **silently**. The
Kubernetes API audit log (T1.4) covers the control plane; it is blind to
syscall-level anomalies inside a running pod.

## Proposed Approach

Deploy **Falco** (CNCF runtime security) using the **modern eBPF (CO-RE)**
driver in a dedicated `falco` namespace. Five Harbor-specific detection rules
are layered **additively** over the default ruleset via the `customRules`
mechanism. Phase 1 is shadow/stdout-only; phase 2 wires Falcosidekick.

### Key decisions

| Decision | Choice | Why |
|---|---|---|
| Driver | `modern_ebpf` (CO-RE) | No DKMS; survives kernel upgrades |
| Namespace | Dedicated `falco` | PSA `restricted` stays on `harbor` |
| PSA | `privileged` on `falco` only | Falco needs elevated capabilities |
| Rules | Additive via `customRules` | Never fork upstream rules |
| Rollout | Shadow stdout → Falcosidekick | Triage FPs before live alerts |
| Kyverno | `disallow-privilege-escalation` excludes `falco` ns | Coordinate with T2.4 |

## Deliverables

| File | Description |
|---|---|
| `deploy/falco/values-falco.yaml` | Helm values: driver, socket, resources, JSON stdout, priority |
| `deploy/falco/rules/harbor_rules.yaml` | 5 Harbor-specific additive Falco rules |
| `deploy/falco/falcosidekick-values.yaml` | Phase-2 stub (all commented out) |
| `deploy/falco/kustomization.yaml` | Kustomize entrypoint + namespace with PSA labels |
| `deploy/falco/README.md` | Install runbook, smoke tests, triage notes, rollback |

## Implementation Checklist

- [ ] Create `deploy/falco/rules/harbor_rules.yaml` with 5 custom rules
  - [ ] Harbor Shell Spawned — CRITICAL, scoped to `harbor` namespace
  - [ ] Harbor Privileged Exec — CRITICAL
  - [ ] Harbor Unexpected Outbound — WARNING, approved port allowlist
  - [ ] Harbor Sensitive File Read — WARNING (`/etc/shadow`, `/etc/passwd`, key material)
  - [ ] Harbor Secret Mount Access by Foreign Process — CRITICAL
  - [ ] Validate: `falco --validate deploy/falco/rules/harbor_rules.yaml`
- [ ] Create `deploy/falco/values-falco.yaml`
  - [ ] `driver.kind: modern_ebpf`
  - [ ] `collectors.containerd.socket: /run/k3s/containerd/containerd.sock`
  - [ ] Resources: limits cpu 500m / memory 512Mi, requests cpu 100m / memory 128Mi
  - [ ] `falco.jsonOutput: true`
  - [ ] `falco.priority: notice`
  - [ ] `customRules` wiring for `harbor_rules.yaml`
- [ ] Create `deploy/falco/falcosidekick-values.yaml` (commented-out phase-2 stub)
- [ ] Create `deploy/falco/kustomization.yaml`
  - [ ] Falco namespace with `pod-security.kubernetes.io/enforce: privileged`
  - [ ] Document Kyverno `disallow-privilege-escalation` exclusion requirement
- [ ] Create `deploy/falco/README.md`
  - [ ] Install runbook (`helm repo add`, `helm install -f values-falco.yaml`)
  - [ ] Verification smoke tests
  - [ ] Per-rule triage notes for all 5 rules
  - [ ] Shadow-then-alert tuning loop procedure
  - [ ] Rollback instructions

## Validation

```bash
falco --validate deploy/falco/rules/harbor_rules.yaml
helm lint deploy/falco/
helm template falco falcosecurity/falco -f deploy/falco/values-falco.yaml \
  | kubectl apply --dry-run=client -f -
go build ./... && go vet ./... && go test ./...
make agent-check
openspec validate falco-runtime-detection-752575e3 --strict
```

## Definition of Done

- All 5 Harbor custom rules present and `falco --validate` exits 0
- `helm lint` exits 0
- `make agent-check` green (no Go changes)
- README covers all 5 rules with triage notes
- OpenSpec verification passes
- PR merged on `main`
