# Proposal: Validate Relay-Enabled Helm Rendering in CI

## Problem

The `helm-lint` CI job validates `deploy/helm/` only with default values. Because
`relay.enabled` defaults to `false`, the relay ConfigMap, Deployment, Secret,
Service, and NetworkPolicy templates are excluded from that check. Regressions
in those optional templates can therefore merge while the Helm job remains
green.

## Proposed Solution

Extend the existing `.github/workflows/ci.yml` Helm job to exercise both the
default chart configuration and `--set relay.enabled=true`. For each
configuration, run `helm lint`, render with `helm template`, and parse every
rendered YAML document without contacting a Kubernetes cluster. Keep the check
compact and fast, and retain the existing default validation.

Before committing the implementation, deliberately introduce an invalid relay
template expression, demonstrate that the relay-enabled validation fails, and
revert the deliberate change.

## Non-goals

- Deploying the chart to a Kubernetes cluster.
- Changing relay templates or chart defaults.
- Validating every possible Helm values combination.
- Adding visual or runtime application testing.

## Success Criteria

- CI validates both default and relay-enabled chart configurations.
- Each configuration passes `helm lint`, `helm template`, and YAML parsing.
- A deliberate relay-template defect makes the new guard fail.
- The deliberate defect is absent from the committed changes.
