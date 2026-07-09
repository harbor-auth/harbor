---
# Feature doc template — copy to docs/features/<kebab-slug>.md and fill in.
# Then add a row to docs/README.md (Features table). A feature doc describes
# behavior AS BUILT: the code is the source of truth (docs/README.md rule).
title: <Human-readable feature name>
status: implemented        # planned | in-progress | implemented | deprecated
design_refs: [§0.0]        # DESIGN.md sections this realizes (house § convention)
code:  [internal/<pkg>/]   # repo paths that implement this feature (drift anchor)
spec:  []                  # contract paths, e.g. api/openapi/harbor.yaml (or [])
tests: [internal/<pkg>/]   # test paths covering this feature
depends_on: []             # other feature slugs this builds on (or [])
plan: null                 # provenance: plans/<slug>.md it graduated from, or null
last_reconciled: YYYY-MM-DD # date the doc was last verified against the code
---

# <Feature name>

## Summary

<!-- One paragraph: what this capability is and why it exists. Link the DESIGN
     § it realizes. Keep it grep-friendly (mention the key package names). -->

## Behavior (as-built)

<!-- What the code ACTUALLY does today — the observable behavior, edge cases,
     and any deliberate scaffolds/limitations. This is the section `@docs
     reconcile` spot-checks against the code, so keep claims concrete and
     verifiable (e.g. "PKCE S256 only; `plain` is rejected"). -->

## Interfaces / Endpoints

<!-- Public surface: HTTP endpoints, exported Go types/functions, CLI flags,
     env vars. For endpoints, note method + path + success/error shape. -->

## Code map

<!-- Each path that implements the feature + a one-line role. Keep these paths
     in sync with the `code:` frontmatter (reconcile checks path existence). -->

| Path | Role |
|---|---|
| `internal/<pkg>/<file>.go` | <one-line role> |

## Security & privacy invariants

<!-- The security/privacy properties this feature MUST uphold, each citing the
     DESIGN § that mandates it (e.g. §5 region isolation, §6.5 PII-free errors,
     §11.7 open-redirect defense). Reconcile verifies these against the code. -->

## Tests

<!-- Where the behavior is tested + what's covered (and notably what isn't).
     Keep in sync with the `tests:` frontmatter. -->

## Known gaps / TODOs

<!-- Scaffolds to replace, follow-ups, and links to any open plan
     (docs/plans/<slug>.md) that extends this feature. -->
