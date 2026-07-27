# Plan — Falco Runtime Threat Detection (`falco-runtime-detection`)

> **Status:** draft · **Tier:** T3.3 (infra-hardening) · **Target:** `51.89.98.90`
> (RKE2 v1.35.6, single-node, Ubuntu) · **Parent doc:** [`infra-hardening.md`](infra-hardening.md#t33--falco-runtime-threat-detection)

## 1. Problem statement

Every control shipped so far is **preventive** (firewall, NetworkPolicy, PSA, Kyverno,
mTLS) or **forensic-after-the-fact** (API audit log). Nothing watches what actually
*executes* at runtime. If an attacker lands inside a harbor pod — via a supply-chain'd
dependency, an RCE in a handler, or a stolen kubeconfig — today we would learn about it
from the damage, not the intrusion. For an OIDC provider, the attacker's playbook is
predictable: spawn a shell in the hot pod, read mounted Secrets, dump `/etc/passwd`
style recon, and exfiltrate signing material or the Postgres credentials over a new
outbound connection. Each of those steps has a distinctive syscall signature that Falco
detects in real time via eBPF — closing the detection gap between "prevented" and
"already happened".

## 2. Approach

### 2.1 Deliverables (in-repo)

```
deploy/falco/
  values-falco.yaml               # Helm values: modern_ebpf, resource caps, outputs
  rules/
    harbor_rules.yaml             # custom rules + tuning overrides (falco.rulesFiles)
  falcosidekick-values.yaml       # (phase 2) alert routing — webhook/Slack/SMTP
  kustomization.yaml
  README.md                       # install, tuning loop, alert triage runbook
```

### 2.2 Install profile — eBPF, not kernel module

Helm chart `falcosecurity/falco`, pinned version, key values:

- **`driver.kind: modern_ebpf`** — CO-RE eBPF probe, no kernel module compilation, no
  DKMS, no kernel-header dependency; survives Ubuntu kernel upgrades on the RKE2 node
  without rebuilds. A crashing kernel module can take down the *only* node; the eBPF
  probe cannot panic the kernel. This is non-negotiable on a single-node cluster.
- DaemonSet (one pod on our one node) in a dedicated `falco` namespace with PSA
  `privileged` labels — Falco legitimately needs host visibility (`privileged: true`
  or the finer-grained caps the chart offers); it must NOT run in `harbor`.
- Resource caps (`cpu: 500m`, `memory: 512Mi` limits) + `driver` syscall-drop alerting
  enabled, so Falco degrades observably rather than silently under load.
- `collectors.kubernetes` enabled for k8s metadata enrichment (pod/namespace names in
  alerts); container runtime socket path set for RKE2's containerd
  (`/run/k3s/containerd/containerd.sock` — RKE2 uses the k3s path; verified at install).
- Outputs phase 1: JSON to stdout (scraped from pod logs) + `priority: notice`
  threshold. Phase 2: Falcosidekick → Slack/webhook for `warning`+ alerts.

### 2.3 Priority custom rules (`harbor_rules.yaml`)

Falco's default ruleset stays enabled; we add Harbor-scoped rules keyed on
`k8s.ns.name = "harbor"` container fields:

| Rule | Condition (sketch) | Priority |
|---|---|---|
| `Harbor Shell Spawned` | `spawned_process and container and k8s.ns.name=harbor and proc.name in (shell_binaries)` — harbor images are distroless-ish Go binaries; *any* shell exec in them is hostile. | CRITICAL |
| `Harbor Privileged Exec` | `evt.type=execve and k8s.ns.name=harbor and proc.pname=kubectl-exec-like` — kubectl exec/attach into harbor pods (also visible in API audit log; Falco gives the runtime side). | WARNING |
| `Harbor Unexpected Outbound` | `outbound and k8s.ns.name=harbor and not fd.sport in (allowed)` and destination not in {postgres, redis, DNS, 443, SMTP 587/465} — mirrors the egress NetworkPolicy allowlist, catching anything that slips through (e.g. 443-tunneled exfil to unknown IPs can phase-2 into an IP allowlist for KMS/JWKS endpoints). | WARNING |
| `Harbor Sensitive File Read` | `open_read and k8s.ns.name=harbor and fd.name in (/etc/passwd, /etc/shadow)` — classic post-exploit recon. | WARNING |
| `Harbor Secret Mount Access by Foreign Process` | `open_read and fd.name startswith /var/run/secrets or fd.name startswith /etc/harbor-secrets and not proc.name in (harbor-hot, harbor-mgmt)` — only the harbor binaries may read mounted secret volumes. | CRITICAL |

Rule-authoring conventions: every custom rule gets a `tags: [harbor, T3.3]` entry, an
`output` template including `k8s.pod.name`, `proc.cmdline`, `fd.name`, and a README
triage note (what it means, expected false-positive sources, first response step).

### 2.4 Tuning loop (the part everyone skips)

Falco's failure mode is alert fatigue → muted channel → useless. The plan bakes in:
1. **Week 1 shadow mode:** default + custom rules at `notice`+, stdout only. Collect.
2. Triage every firing rule: legitimate (e.g. postgres image runs `sh` in init) →
   add a scoped exception (`macro`/`list` override in `harbor_rules.yaml`, committed +
   reviewed — never edit defaults in place).
3. Only after a quiet week: wire Falcosidekick alerting for `warning`+.
False-positive exceptions are **git-reviewed rule changes**, giving an auditable
detection-engineering history.

### 2.5 Key decisions

1. **modern_ebpf over kernel module** — single-node blast-radius + no header churn.
2. **Dedicated privileged `falco` namespace** — don't weaken `harbor` PSA.
3. **Default ruleset retained + additive Harbor rules** — never fork upstream rules;
   override via the chart's `customRules` mechanism so upstream updates flow.
4. **Shadow-then-alert rollout** — detection quality over launch speed.
5. **Falco complements, not replaces, the audit log** — audit log sees the API plane;
   Falco sees the syscall plane; an attacker must now evade both.

## 3. Implementation steps

1. `values-falco.yaml` per §2.2 (pinned chart, modern_ebpf, RKE2 containerd socket,
   resource caps, k8s metadata collector, JSON output).
2. `rules/harbor_rules.yaml` with the five rules + empty exceptions scaffold.
3. Kyverno/PSA interplay check: `falco` namespace excluded from
   `disallow-privilege-escalation` scope (coordinate with `kyverno-policies` — Falco is
   a legitimate privileged workload; add the namespace exclusion there if both land).
4. `README.md`: install runbook, verification, tuning loop (§2.4), per-rule triage
   notes, rollback (`helm uninstall falco` is side-effect-free — detection only, never
   in any traffic or admission path).
5. Wire into ArgoCD app-of-apps.
6. Phase 2 (separate follow-up, stubbed in repo): `falcosidekick-values.yaml` routing.

## 4. Validation

- `helm lint` against the values files (chart pulled at pinned version);
  `helm template falcosecurity/falco -f deploy/falco/values-falco.yaml | kubectl apply --dry-run=client -f -` clean.
- Rules syntax: `falco --validate deploy/falco/rules/harbor_rules.yaml` (falco container
  run locally/in CI — no cluster needed).
- On-cluster smoke, one per rule class:
  - `kubectl exec -n harbor deploy/harbor-hot -- /bin/sh -c id` (if a shell exists in
    the image; otherwise an ephemeral debug container) → `Harbor Shell Spawned` fires;
  - `cat /etc/passwd` inside a harbor pod → sensitive-file rule fires;
  - `wget http://example.com` from a harbor pod → unexpected-outbound fires (and is
    *also* dropped by the egress NetworkPolicy — both layers verified in one test).
- Health: `falco` pod Ready; **zero `syscall drops` events** under normal Harbor load
  (OIDC flow smoke test running); node CPU overhead < 3%.
- Detection is out-of-band: kill the Falco pod mid-OIDC-flow → Harbor traffic unaffected.
- Repo checks: `go build ./... && go vet ./... && go test ./... && make agent-check` green.
