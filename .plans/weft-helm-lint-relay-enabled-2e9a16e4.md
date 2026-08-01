# Helm relay CI validation

1. Inspect the existing Helm CI job and relay-only templates.
2. Extend the job with default and relay-enabled matrix configurations.
3. For each configuration, lint, render, and parse every rendered YAML document.
4. Deliberately break a relay-only template and verify only the new configuration catches it, then restore it.
5. Validate both configurations and the workflow, commit, rebase, and push.
