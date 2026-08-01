# Tasks: Validate Relay-Enabled Helm Rendering in CI

## Prerequisites

- Relay templates exist under `deploy/helm/templates/` and remain disabled by default.
- The existing `helm-lint` job in `.github/workflows/ci.yml` is green on `main`.

## Implementation

- [ ] Extend `.github/workflows/ci.yml` so the existing `helm-lint` job validates both default values and `--set relay.enabled=true`.
- [ ] For both configurations, run `helm lint`, `helm template`, and parse all rendered YAML documents without a cluster dependency.
- [ ] Keep the job compact and retain the existing default validation.

## Tests

- [ ] Run the default lint, render, and YAML-parse commands successfully.
- [ ] Run the relay-enabled lint, render, and YAML-parse commands successfully.
- [ ] Temporarily break a relay-only template, confirm the relay-enabled command fails, then restore the template before commit.
- [ ] Confirm the restored worktree contains no relay-template changes and both configurations pass again.

## Validation

- [ ] Validate `.github/workflows/ci.yml` with the repository's available workflow/config checks.
- [ ] Run `openspec validate helm-lint-relay-enabled-2e9a16e4 --strict`.
