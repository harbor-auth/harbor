# Design: Validate Relay-Enabled Helm Rendering in CI

## Context

The current `helm-lint` job contains one checkout step and one `helm lint
deploy/helm/` invocation. Relay templates are conditionally rendered only when
`relay.enabled` is true.

## Decisions

### Exercise configurations within the existing job

Use a compact matrix or two explicit steps in the existing `helm-lint` job.
The configurations are defaults and relay enabled via `--set
relay.enabled=true`. This preserves the existing default check without adding a
second job or cluster dependency.

### Lint, render, and parse every configuration

For each configuration, run `helm lint` and `helm template`. Save or pipe the
rendered manifests into an available YAML parser that reads all multi-document
output. Rendering exercises conditional templates; parsing independently
rejects malformed YAML that Helm may emit successfully.

The parser must be installed or invoked in a reproducible, lightweight way on
`ubuntu-latest`, and the shell must fail if any lint, render, or parse command
fails.

### Prove the negative path manually before commit

Temporarily break a template guarded by `.Values.relay.enabled`, run the same
relay-enabled validation command used by CI, and confirm a non-zero result.
Restore the template and rerun both configurations successfully. The temporary
defect is verification evidence only and must never be committed.

## Risks and Mitigations

- **A parser reads only the first document:** select an invocation that loads
  all YAML documents.
- **Shell quoting drops optional Helm arguments:** use explicit steps or a
  matrix representation whose empty/default case remains valid.
- **The negative proof tests a different path:** break a relay-only template
  and execute exactly the relay-enabled CI command.
