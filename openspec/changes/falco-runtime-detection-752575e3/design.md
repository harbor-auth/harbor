# Design: Falco eBPF runtime threat detection (T3.3)

## Key Decisions

### Decision 1: modern_ebpf (CO-RE) driver — no kernel module
**Chosen:** `driver.kind=modern_ebpf` — the eBPF CO-RE (Compile Once, Run
Everywhere) driver that ships in Falco ≥ 0.35. No DKMS, no kernel module build,
no kernel-header dependency.
**Rationale:** The cluster is a single RKE2 node on Ubuntu 24.04 with a
regularly upgraded kernel. Kernel modules must be rebuilt on every kernel
upgrade; a failed rebuild silently disables Falco. CO-RE eBPF compiles against
BTF type information embedded in the running kernel and survives upgrades
transparently. Blast radius on a single-node cluster is already bounded — CO-RE
is the correct default for managed/upgraded kernels.
**Alternatives considered:** `driver.kind=ebpf` (classic eBPF — requires kernel
headers at runtime, rejected — header dependency adds ops burden);
`driver.kind=module` (kernel module — rejected — DKMS dependency, breaks on
kernel upgrade, higher blast radius).

### Decision 2: Dedicated `falco` namespace with PSA `privileged` labels
**Chosen:** Falco runs in its own `falco` namespace with
`pod-security.kubernetes.io/enforce: privileged`. The `harbor` namespace retains
`restricted`.
**Rationale:** Falco requires host syscall visibility — it needs
`hostPID: false` but does need elevated capabilities (`CAP_SYS_PTRACE`,
`CAP_SYS_ADMIN` for eBPF map manipulation, `CAP_NET_ADMIN`). These are
incompatible with PSA `restricted`. Isolating Falco in its own namespace with
`privileged` PSA avoids poisoning the `harbor` namespace's `restricted` policy
and makes the trust boundary explicit. The `harbor` namespace retains full
`restricted` enforcement — Falco's privilege grant is scoped to its own
namespace only.
**Alternatives considered:** Running Falco in the `harbor` namespace (rejected —
would require relaxing `restricted` PSA for all harbor pods); using PSA
`baseline` for Falco (insufficient — Falco's capabilities exceed `baseline`).

### Decision 3: Additive rules via `customRules` — never fork upstream
**Chosen:** Harbor-specific rules are loaded via Falco's `customRules` Helm
value (appended after the default ruleset). The upstream default rules are never
modified.
**Rationale:** Forking Falco's upstream rules creates a maintenance burden
(manual merges on every Falco upgrade) and risks silently losing upstream
security improvements. `customRules` is the idiomatic, officially supported
extension point — Harbor rules are layered additively and survive chart upgrades
without conflict.
**Alternatives considered:** Patching the default rules directly (rejected —
maintenance burden, breaks on Falco upgrades); replacing the default ruleset
entirely (`falco.rules_file` override, rejected — loses upstream detections).

### Decision 4: Shadow-then-alert rollout (stdout first, Falcosidekick second)
**Chosen:** Phase 1 (this change): JSON stdout output only — no external
alerting. Phase 2 (future): wire Falcosidekick for alert routing once false
positives are triaged.
**Rationale:** New Falco rules in a production environment always produce false
positives on first deployment (legitimate tooling, init containers, debug
sessions). Routing untriaged alerts to PagerDuty causes alert fatigue and
erodes trust in the detection system. Stdout-only phase lets operators review
`kubectl logs` output and git-commit rule exceptions for real false positives
before live alerting is enabled. The Falcosidekick values stub is committed now
so phase 2 is a two-line uncomment, not a new design.
**Alternatives considered:** Alert immediately on install (rejected — untriaged
FP flood degrades signal quality); audit/dry-run mode (rejected — Falco has no
built-in dry-run; stdout is functionally equivalent and the standard approach).

### Decision 5: Kyverno `disallow-privilege-escalation` exclusion for `falco` namespace
**Chosen:** Document in `kustomization.yaml` and the README that the `falco`
namespace MUST be added to the Kyverno `disallow-privilege-escalation`
ClusterPolicy exclusion list (when Kyverno T2.4 is deployed).
**Rationale:** The Kyverno `disallow-privilege-escalation` policy (T2.4)
enforces `allowPrivilegeEscalation: false` cluster-wide. Falco's eBPF driver
needs `allowPrivilegeEscalation: true` for capability grants. Without the
exclusion, Kyverno blocks Falco pod admission. The exclusion is minimal and
scoped to the `falco` namespace only.
**Alternatives considered:** Omit the exclusion note (rejected — would cause a
confusing Kyverno admission block when T2.4 is deployed, creating an invisible
dependency); apply a per-pod annotation exclusion (rejected — Helm values
control pod spec; namespace-level exclusion is simpler and auditable).

## Security & Privacy Invariants

- Falco has no access to application data, PostgreSQL, Redis, or Harbor secrets.
  NetworkPolicy on the `falco` namespace restricts egress to DNS and (phase 2)
  the Falcosidekick service only.
- No PII flows through Falco rules — rules fire on syscall metadata
  (process name, file path, network tuple) not on HTTP bodies or JWT content.
- Custom rules are additive only; the default ruleset is never weakened or
  overridden.
- Resource caps (cpu 500m, memory 512Mi) prevent Falco from starving harbor
  workloads on the single-node cluster.
