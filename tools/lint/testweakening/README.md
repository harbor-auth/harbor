# testweakening — anti-Goodhart tamper detector (Foundation F5)

A stdlib-only detector that inspects the diff against a base branch and flags the
classic "make it go green by weakening the check" moves. Weakening a check to
pass is the Goodhart failure: the metric (green CI) is met while the target
(correct, protected code) is quietly abandoned.

## What it flags

| Signal | Severity | Why |
|---|---|---|
| Deleted `Test`/`Benchmark`/`Fuzz` function (net removal per file) | **FAIL** | fewer tests = weaker coverage |
| Removed `//harbor:invariant INV-XXX` tag | **FAIL** | an invariant loses its enforcing anchor (F1) |
| Modified frozen `*_vectors.json` without a `VECTOR-CHANGE:` marker | **FAIL** | a crypto-output change slipping through unreviewed (F2) |
| New `t.Skip(` / `t.SkipNow(` | WARN → exit 1 | a test being silenced; justify or remove |
| Naked `//nolint` (no `:linter // reason`) | WARN → exit 1 | a lint being muzzled |

## Why

CODEOWNERS gates the *files*; this tool gates the *diff*. Together (plus branch
protection on `agent-check`, Foundation F7) they make weakening a guardrail an
explicit, reviewed act rather than a quiet side effect of chasing green.

## Run it

```bash
go run ./tools/lint/testweakening --base origin/main   # or: BASE=origin/main make tamper-check
```

If no baseline is available (a fresh clone with no upstream) it prints a note and
exits 0 — it never blocks work with nothing to compare against. CI runs it with
the real PR base (`origin/<base_ref>`).
