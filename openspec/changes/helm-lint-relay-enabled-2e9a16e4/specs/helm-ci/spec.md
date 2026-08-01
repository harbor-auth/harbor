# Helm CI Validation Specification

## ADDED Requirements

### Requirement: CI SHALL validate the Helm chart with default values

The existing `helm-lint` job SHALL continue to run `helm lint` and SHALL render
`deploy/helm/` with `helm template` using default values. It MUST parse every
rendered YAML document and MUST fail when linting, rendering, or YAML parsing
fails.

#### Scenario: Default chart configuration is valid

**Given** the committed default values in `deploy/helm/values.yaml`
**When** the `helm-lint` job validates the default configuration
**Then** Helm linting, template rendering, and parsing of all rendered YAML documents exit successfully

### Requirement: CI SHALL validate relay-enabled templates

The `helm-lint` job SHALL separately validate `deploy/helm/` with at least
`--set relay.enabled=true`. It SHALL run `helm lint`, render with `helm
template`, and parse every rendered YAML document. The validation MUST NOT
require access to a Kubernetes cluster.

#### Scenario: Relay-enabled chart configuration is valid

**Given** the chart is configured with `relay.enabled=true`
**When** the `helm-lint` job validates that configuration
**Then** relay-only resources are rendered and Helm linting, rendering, and YAML parsing exit successfully without a cluster

#### Scenario: A relay-only template is invalid

**Given** a defect exists in a template rendered only when `relay.enabled=true`
**When** the relay-enabled validation runs
**Then** at least one lint, render, or YAML-parse command exits non-zero and fails the job

### Requirement: The relay guard SHALL be proven before commit

The implementation SHALL be tested by temporarily introducing a defect into a
relay-only template and confirming the relay-enabled check fails. The defect
MUST be reverted before commit, after which both default and relay-enabled
checks MUST pass.

#### Scenario: Deliberate defect is absent from the final change

**Given** the negative-path proof has produced a failing result
**When** the implementation is prepared for commit
**Then** the relay template matches its pre-proof content and both chart configurations validate successfully
