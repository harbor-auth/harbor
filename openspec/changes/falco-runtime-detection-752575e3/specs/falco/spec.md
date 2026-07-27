# Spec: Falco eBPF runtime threat detection (T3.3)

Deploys Falco with the modern eBPF (CO-RE) driver in a dedicated privileged
namespace, layering five Harbor-specific additive detection rules over the
default ruleset via the `customRules` mechanism. Phase 1 shadow mode: JSON
stdout only. Realises T3.3 of docs/plans/infra-hardening.md.

## ADDED Requirements

### Requirement: REQ-001 modern_ebpf driver — no kernel module

The system SHALL deploy Falco with `driver.kind=modern_ebpf` (CO-RE eBPF).
The deployment MUST NOT use `driver.kind=module` (kernel module) or
`driver.kind=ebpf` (classic eBPF requiring kernel headers).

#### Scenario: Falco starts with modern_ebpf driver

**Given** the Helm values at `deploy/falco/values-falco.yaml`
**When** `helm template` renders the Falco DaemonSet
**Then** the rendered spec contains `driver.kind=modern_ebpf` and no
kernel-module init container

### Requirement: REQ-002 Dedicated `falco` namespace with PSA privileged

The system SHALL create a `falco` namespace with
`pod-security.kubernetes.io/enforce: privileged`. The `harbor` namespace
MUST retain `pod-security.kubernetes.io/enforce: restricted` unchanged.

#### Scenario: Falco namespace has privileged PSA label

**Given** the `deploy/falco/kustomization.yaml` or equivalent namespace manifest
**When** `kubectl apply` renders the namespace
**Then** the `falco` namespace has `pod-security.kubernetes.io/enforce: privileged`
and the `harbor` namespace is unmodified

### Requirement: REQ-003 Five Harbor-specific custom rules, additive

The system SHALL define exactly five Harbor custom Falco rules in
`deploy/falco/rules/harbor_rules.yaml`, loaded via the Falco `customRules`
mechanism (additive over the default ruleset). The default ruleset MUST NOT
be forked, patched, or replaced.

| Rule name | Priority |
|---|---|
| Harbor Shell Spawned | CRITICAL |
| Harbor Privileged Exec | CRITICAL |
| Harbor Unexpected Outbound | WARNING |
| Harbor Sensitive File Read | WARNING |
| Harbor Secret Mount Access by Foreign Process | CRITICAL |

#### Scenario: Custom rules validate cleanly

**Given** `deploy/falco/rules/harbor_rules.yaml`
**When** `falco --validate deploy/falco/rules/harbor_rules.yaml` runs
**Then** the command exits 0 with no syntax or schema errors

#### Scenario: Rules are additive — upstream rules intact

**Given** the Falco values `customRules` key references `harbor_rules.yaml`
**When** Falco loads rules at startup
**Then** all five Harbor rules are active AND upstream default rules are
still evaluated (not replaced or suppressed)

### Requirement: REQ-004 Resource caps prevent noisy-neighbour starvation

The system SHALL configure Falco with resource limits of cpu≤500m and
memory≤512Mi, and requests of at least cpu=100m and memory=128Mi.

#### Scenario: Resource limits are rendered in the DaemonSet

**Given** `deploy/falco/values-falco.yaml`
**When** `helm template` renders the Falco DaemonSet
**Then** each container spec has `limits.cpu: 500m` and `limits.memory: 512Mi`

### Requirement: REQ-005 JSON stdout output, notice+ priority (phase 1 shadow)

The system SHALL configure Falco to emit alerts as JSON to stdout with a
minimum priority threshold of `notice`. No external webhook or Falcosidekick
routing SHALL be active in phase 1.

#### Scenario: Alerts emitted as JSON stdout

**Given** the deployed Falco instance
**When** a rule fires
**Then** the alert appears in `kubectl logs` as a single-line JSON object
with `output_fields`, `priority`, `rule`, and `time` keys

#### Scenario: Falcosidekick is not wired in phase 1

**Given** `deploy/falco/falcosidekick-values.yaml`
**When** the file is inspected
**Then** all Falcosidekick routing configuration is commented out (stub only)

### Requirement: REQ-006 Helm lint and dry-run pass

The system SHALL provide a Helm-lintable `deploy/falco/` chart structure such
that `helm lint deploy/falco/` exits 0 and `helm template | kubectl apply
--dry-run=client` succeeds against the cluster API.

#### Scenario: helm lint passes

**Given** `deploy/falco/` with `Chart.yaml`, `values-falco.yaml`
**When** `helm lint deploy/falco/` runs
**Then** exit code is 0 with no errors (warnings acceptable)

### Requirement: REQ-007 Install runbook and rollback in README

The system SHALL include `deploy/falco/README.md` covering: install runbook,
verification smoke tests, per-rule triage notes for all 5 rules, the
shadow-then-alert tuning loop procedure, and rollback instructions.

#### Scenario: README covers all 5 rules

**Given** `deploy/falco/README.md`
**When** the file is read
**Then** each of the 5 Harbor custom rules has a named triage section
describing expected false-positive sources and how to add a rule exception
