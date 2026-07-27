# Proposal: Falco eBPF runtime threat detection (T3.3)

## Problem

Harbor's production cluster has no kernel-level visibility into runtime
behaviour. A compromised container (supply-chain attack, RCE via dependency,
or misconfigured workload) can: spawn a shell, exfiltrate secrets from mounted
volumes, open unexpected outbound connections, or read `/etc/passwd` —
**silently**, with no alerting. Kubernetes audit logging (T1.4) records API-plane
actions; it cannot see syscall-level anomalies inside a running pod.

Without runtime threat detection, the blast radius of any container escape or
RCE is bounded only by what Kubernetes RBAC and NetworkPolicy can prevent — not
by visibility into what actually runs. Post-incident forensics are blind.

## Proposed Solution

Deploy **Falco** (CNCF runtime security) in the `falco` namespace using the
**modern eBPF (CO-RE)** driver — no kernel module, no DKMS, survives kernel
upgrades. Falco tails every syscall via eBPF, evaluates rules, and emits
structured JSON alerts to stdout (week 1 shadow mode), then to Falcosidekick
for routing (phase 2).

Five **Harbor-specific additive rules** are layered over the default ruleset
(never forking upstream):

1. **Harbor Shell Spawned** (CRITICAL) — shell exec inside a `harbor-*` container
2. **Harbor Privileged Exec** (CRITICAL) — `exec` into a privileged harbor pod
3. **Harbor Unexpected Outbound** (WARNING) — outbound connection outside the
   approved port set
4. **Harbor Sensitive File Read** (WARNING) — read of `/etc/shadow`, `/etc/passwd`,
   or private key material
5. **Harbor Secret Mount Access by Foreign Process** (CRITICAL) — a non-harbor
   process reading from a harbor secret mount path

Rollout is **shadow-then-alert**: week 1 JSON stdout only, triage false positives
as git-reviewed rule exceptions, then wire Falcosidekick for routing to PagerDuty
/ Slack.

## Non-Goals

- Replacing Kubernetes NetworkPolicy or Pod Security Admission — Falco is
  additive, not a substitute.
- Falcosidekick alert routing (phase 2 — stub included, not wired).
- Multi-node or multi-cluster Falco federation — single-node RKE2 only.
- SPIFFE/SPIRE integration (T3.5) — out of scope for this change.
- Forking or modifying upstream Falco default rules — Harbor rules are additive
  only via the `customRules` mechanism.

## Success Criteria

- [ ] `helm lint deploy/falco/` passes.
- [ ] `helm template falco falcosecurity/falco -f deploy/falco/values-falco.yaml | kubectl apply --dry-run=client -f -` succeeds.
- [ ] `falco --validate deploy/falco/rules/harbor_rules.yaml` exits 0.
- [ ] All 5 Harbor custom rules are present, correctly scoped to the `harbor` namespace, and syntactically valid.
- [ ] Falco namespace manifest has `pod-security.kubernetes.io/enforce: privileged` label.
- [ ] `make agent-check` is green (no Go changes — pure infra).
