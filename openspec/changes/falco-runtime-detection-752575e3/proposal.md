---
slug: falco-runtime-detection-752575e3
plan: docs/plans/falco-runtime-detection.md
---

# Proposal: Falco eBPF Runtime Threat Detection (T3.3)

## Problem

Every control shipped so far is **preventive** (firewall, NetworkPolicy, PSA, Kyverno,
mTLS) or **forensic-after-the-fact** (API audit log). Nothing watches what actually
*executes* at runtime inside Harbor pods. If an attacker lands inside a Harbor pod —
via supply-chain compromise, RCE, or a stolen kubeconfig — there is no real-time
detection. For an OIDC provider the attacker's playbook is predictable: spawn a shell,
read mounted Secrets, do `/etc/passwd`-style recon, and exfiltrate signing material over
a new outbound connection. Each step has a distinctive syscall signature that Falco
detects in real time via eBPF.

## Proposed Solution

Deploy Falco with the modern eBPF (CO-RE) driver in a dedicated privileged `falco`
namespace, with five Harbor-scoped custom rules layered additively over the default
ruleset via the chart's `customRules` mechanism. Rollout follows a shadow-then-alert
procedure (week 1 stdout-only triage, then Falcosidekick).

**Deliverables:**
- `deploy/falco/values-falco.yaml` — Helm values (modern_ebpf, RKE2 socket, resource caps, JSON output)
- `deploy/falco/rules/harbor_rules.yaml` — 5 Harbor detection rules
- `deploy/falco/falcosidekick-values.yaml` — phase-2 alert routing stub
- `deploy/falco/kustomization.yaml` + `deploy/falco/namespace.yaml` — namespace with PSA privileged labels
- `deploy/falco/README.md` — install runbook, smoke tests, tuning loop, triage notes, rollback

**Key decisions:**
- `modern_ebpf` (CO-RE) NOT kernel module — no DKMS, survives kernel upgrades, single-node blast radius
- Dedicated `falco` namespace with PSA privileged labels; Kyverno must exclude it from `disallow-privilege-escalation`
- Rules additive over default ruleset — never fork upstream
- Shadow-then-alert rollout: triage false positives as git-reviewed exceptions before wiring alerts

## Non-Goals

- Replacing the Kubernetes API audit log (complementary layers)
- Real-time alerting in phase 1 (stdout only; Falcosidekick wired in phase 2)
- Blocking/admission control (detection only — never in the traffic path)
- Cross-region Falco aggregation
- Falco for non-Harbor namespaces (additive scoped rules only)

## Success Criteria

- [ ] `helm lint` and `helm template | kubectl apply --dry-run=client` pass
- [ ] `falco --validate deploy/falco/rules/harbor_rules.yaml` exits 0
- [ ] `kubectl kustomize deploy/falco/` renders without error
- [ ] All 5 Harbor custom rules present with correct priorities (CRITICAL/WARNING)
- [ ] `make agent-check` green (Go build/vet/test unaffected — infra-only change)
