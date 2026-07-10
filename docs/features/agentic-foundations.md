---
title: Agentic development foundations
status: implemented
design_refs: [§1.8, §1.9, §2.2, §5.3, §5.4, §6.5.7, §11.7, §A.8]
code:  [invariants/, flake.nix, Makefile, internal/telemetry/, internal/arch/, tools/agentcheck/, tools/check-design-refs.py, tools/check-doc-links.py, tools/lint/piifields/, tools/lint/testweakening/, .github/workflows/ci.yml, .agents/ENTRYPOINT.md, CODEOWNERS, e2e/]
spec:  []
tests: [invariants/registry_test.go, internal/identity/ppid_vectors_test.go, internal/oidc/pkce_vectors_test.go, internal/arch/arch_test.go, internal/telemetry/]
depends_on: [ppid-identity, oidc-authorization-code]
plan: plans/agentic-foundations.md
last_reconciled: 2026-07-09
---

# Agentic development foundations

## Summary

Harbor is built almost entirely by AI agents, so its guardrails must be **executable, not aspirational**. This feature is 10 mutually-reinforcing foundations that turn DESIGN prose — the §A.8 day-one mitigations, the §11.7 OIDC security invariants, the §6.5.7 telemetry-privacy rules, and the §5.3/§5.4 region isolation rules — into agent-legible checks a truncated context window cannot forget or quietly weaken. It realizes §1.9 (the living toolkit) *operationally* and does **not** change `DESIGN.md`; it makes the existing invariants enforceable. The keystone is a single trusted command:

```bash
make agent-check
```

which fails closed, aggregates every check, and emits a structured verdict (`check-results.json`) that is identical locally and in CI.

## Behavior (as-built)

| # | Foundation | What it does now | Key artifact |
|---|---|---|---|
| 1 | **Executable invariants registry** (keystone) | A meta-test parses `registry.yaml` and fails the build if any entry lacks a real `//harbor:invariant INV-XXX`-tagged test, or if any `enforced_by: pkg:TestName` names a test that does not exist. | `invariants/registry.yaml`, `invariants/registry_test.go` |
| 2 | **Golden vector corpus** (frozen) | Byte-equality tests over hand-computed PPID (HMAC-SHA256) and PKCE S256 vectors — including the RFC 7636 reference vector. Tests never regenerate expectations; a change requires a `VECTOR-CHANGE:` review. | `internal/{identity,oidc}/testdata/*_vectors.json` + `*_vectors_test.go` |
| 3 | **Fail-closed hermetic toolchain** | Every tool-dependent Makefile recipe exits `1` with an install hint when a tool is missing (never a silent skip). `flake.nix` pins the toolchain; a human-only `SOFT=1` escape downgrades a missing tool to a warning locally. | `flake.nix`, `Makefile` |
| 4 | **Agent ENTRYPOINT + context map** | A mandated first-read page (the one trusted command, the knowledge hierarchy, the hard rules) plus per-package `doc.go` files mapping each `internal/<domain>` to its DESIGN § and enforcing invariants. | `.agents/ENTRYPOINT.md`, `internal/*/doc.go` |
| 5 | **Anti-Goodhart tamper guards** | `tamper-check` flags dropped `//harbor:invariant` tags, removed test functions (by name), new `t.Skip`, naked `//nolint`, and unreviewed frozen-vector edits; `coverage-ratchet` fails if security-critical coverage drops below the floor. `CODEOWNERS` gates the guardrail paths. | `CODEOWNERS`, `tools/lint/testweakening/`, Makefile `coverage-ratchet` |
| 6 | **Structured check output** | `make agent-check` runs gofmt · build · vet · test · invariants · piifields · golangci-lint · spectral · buf lint · docs-design-refs · docs-links and writes `check-results.json` (schema `harbor.agent-check/v1`, `overall` = `pass\|fail\|error`, per-check `status`/`exit_code`/`duration_ms`) — a skipped check is never counted as a pass, and a missing linter is an `error`, not a pass. The docs checks (design_refs resolution + relative-link integrity) are also exposed standalone via `make docs-check`. | `tools/agentcheck/`, `tools/check-design-refs.py`, `tools/check-doc-links.py`, Makefile `agent-check`/`docs-check` |
| 7 | **CI as the agent-readable outer loop** | Runs `nix develop -c make agent-check` (identical to local) plus `tamper-check`, `coverage-ratchet`, and `make generate-check` (codegen-drift), posts `check-results.json` as a sticky PR comment, and a final gate step re-fails the job if any check failed. Additionally runs a dedicated Docker-enabled `e2e` job (`nix develop -c make conformance`) exercising the F8 harness. | `.github/workflows/ci.yml` |
| 8 | **Agent-runnable local e2e OIDC harness** | Drives authorize→token→JWKS including §11.7 negatives, behind an `e2e` build tag (Docker-backed) so it is excluded from the default build. Now wired into the `make conformance` §1.8 Stage-7 gate and run in CI via a dedicated Docker-enabled `e2e` job. | `e2e/docker-compose.yml`, `e2e/flow_test.go` |
| 9 | **Architecture import-boundary fitness tests** | Asserts `cmd/harbor-hot` does not transitively import `pgx`/`internal/gen/db` (stateless hot path, §4.1) and that `internal/region` stays pure (§5.3/§5.4). | `internal/arch/arch_test.go` |
| 10 | **PII-in-telemetry deny-by-default guard** | `internal/telemetry` is the sole allow-listed `slog` wrapper; the `piifields` analyzer (wired into agent-check) fails on PII log/metric/trace keys (§6.5.7). | `internal/telemetry/`, `tools/lint/piifields/` |

The anti-Goodhart guards (F5) run in **CI, not in `agent-check`**, because they need git history (a diff against a base ref); `agent-check` is deliberately history-free so it behaves identically on a fresh clone.

## Interfaces / Endpoints

The developer/agent surface (all via `make`, `go run`, or `nix`):

| Surface | Purpose |
|---|---|
| `make agent-check` | The single trusted verdict → writes `check-results.json`. |
| `make tamper-check BASE=<ref>` | Anti-Goodhart diff scan vs a base ref (F5; CI-side). |
| `make coverage-ratchet` | Fail if identity/oidc/crypto coverage < floor (F5). |
| `make conformance` | §1.8 Stage-7 gate: runs the F8 e2e OIDC harness (then the OIDF/WebAuthn suites when present). |
| `make validate` | Fast inner loop: fmt · vet · golangci-lint · spectral · buf · codegen-drift. |
| `make docs-check` | Validate docs integrity: every `design_refs §` resolves in `DESIGN.md`'s map + no broken relative links. |
| `nix develop` | Drop into the pinned, hermetic toolchain (F3). |
| `go run ./tools/lint/piifields ./...` | Standalone PII-in-telemetry analyzer (F10). |
| `go run ./tools/lint/testweakening --base <ref>` | Standalone test-weakening detector (F5). |
| `.agents/ENTRYPOINT.md` | Mandated first-read for any agent. |
| `invariants/registry.yaml` | The single source of the executable invariants. |

Conventions:

- **`//harbor:invariant INV-XXX`** — tag placed on the enforcing test; the meta-test requires one per registry entry.
- **`VECTOR-CHANGE:`** — required PR trailer + human review for any edit to a frozen golden vector.
- **`e2e` build tag** — the e2e harness (F8) is excluded from the default build/test and requires Docker.

## Code map

| Path | Role |
|---|---|
| `invariants/registry.yaml` | The executable invariants registry (§A.8/§11.7 → tests). |
| `invariants/registry_test.go` | Meta-test: every invariant must have a live, tagged, existing test. |
| `internal/identity/testdata/ppid_vectors.json` | Frozen PPID HMAC-SHA256 golden vectors (F2). |
| `internal/identity/ppid_vectors_test.go` | Byte-equality test for the PPID vectors. |
| `internal/oidc/testdata/pkce_vectors.json` | Frozen PKCE S256 golden vectors incl. RFC 7636 (F2). |
| `internal/oidc/pkce_vectors_test.go` | Byte-equality test for the PKCE vectors. |
| `flake.nix` | Pinned, hermetic dev toolchain (F3). |
| `Makefile` | Fail-closed recipes; `agent-check`, `tamper-check`, `coverage-ratchet`, `validate` targets. |
| `.agents/ENTRYPOINT.md` | Mandated first-read; the one trusted command + hard rules (F4). |
| `internal/*/doc.go` | Per-package context map: domain → DESIGN § → invariants (F4). |
| `CODEOWNERS` | Review gate on guardrail paths (F5). |
| `tools/agentcheck/` | Runs the check suite and emits `check-results.json` (F6). |
| `tools/check-design-refs.py` | Validates `design_refs` frontmatter in `docs/features/*.md` resolve in `DESIGN.md`'s `§ → file` map (F6 docs integrity). |
| `tools/check-doc-links.py` | Verifies every relative markdown link in `docs/` resolves to a real file on disk (F6 docs integrity). |
| `tools/lint/piifields/` | PII-in-telemetry analyzer (F10). |
| `tools/lint/testweakening/` | Anti-Goodhart test-weakening detector (F5). |
| `.github/workflows/ci.yml` | The agent-readable outer loop + sticky PR comment + gate (F7). |
| `e2e/docker-compose.yml`, `e2e/flow_test.go` | Composed OIDC flow harness behind the `e2e` tag (F8). |
| `internal/arch/arch_test.go` | Import-boundary fitness tests (F9). |
| `internal/telemetry/` | Deny-by-default allow-listed telemetry wrapper (F10). |

## Security & privacy invariants

All are enforced executably; `invariants/registry.yaml` is the single source and `invariants/registry_test.go` is the enforcer.

- **Asymmetric-only signing** — ES256/EdDSA only; reject `alg:none`/HS (`INV-SIGN-ASYM-ONLY`, §3.3/§7.3).
- **PKCE S256 mandatory** — `plain` rejected (`INV-PKCE-MANDATORY`, §11.7).
- **Exact `redirect_uri` match** — against a pre-registered allowlist (`INV-REDIRECT-EXACT`, §11.7).
- **Single-use authorization codes** — reuse ⇒ `invalid_grant` (`INV-CODE-SINGLE-USE`, §11.7).
- **Generic `invalid_grant`** — token failures never reveal which check failed (`INV-INVALID-GRANT-GENERIC`, §11.7).
- **Constant-time comparison** — for codes/PKCE/secrets/tokens (`INV-CONSTANT-TIME-COMPARE`, §11.7).
- **Per-user pairwise secret** — no global correlation secret; sectors non-correlating (`INV-PPID-PAIRWISE-SECRET`, §3.2).
- **No PII in telemetry** — deny-by-default allow-listing via `internal/telemetry`, gated by `piifields` (§6.5.7).
- **Region isolation** — the hot path stays stateless and `internal/region` stays pure; no cross-region PII/keys (§5.3/§5.4).

## Tests

- **Invariants meta-test** (`invariants/registry_test.go`) — structural validity + tag existence + `enforced_by` test existence.
- **Golden-vector byte-equality** (`internal/identity/ppid_vectors_test.go`, `internal/oidc/pkce_vectors_test.go`) — recompute and byte-compare against frozen expectations; never regenerate.
- **Architecture fitness** (`internal/arch/arch_test.go`) — hot path ⇏ DB; region stays pure.
- **Telemetry** (`internal/telemetry/*_test.go`) + the `piifields` analyzer — deny-by-default allow-list.

`make agent-check` aggregates gofmt/build/vet/test/invariants/piifields/golangci-lint/spectral/buf-lint/docs-design-refs/docs-links into `check-results.json`. `tamper-check`, `coverage-ratchet`, and codegen-drift (`make generate-check`) are CI-side (they need git history). Current state: **all green**, coverage **78.8%** on security-critical packages (floor **75%**).

## Known gaps / TODOs

1. **`flake.lock` is not yet committed.** Run `nix flake update` on a machine with Nix so `nix develop` is bit-for-bit reproducible; `CODEOWNERS` already protects the lockfile. Until then the flake pins the channel but not exact revisions.
2. **e2e harness (F8) is now wired into `make conformance` and a dedicated Docker-enabled CI `e2e` job** — it runs on every PR (`nix develop -c make conformance`), so authorize→token→JWKS + the §11.7 negatives are exercised against a live harbor-hot. It remains behind the `e2e` build tag (excluded from the default `agent-check`, which stays Docker-free). Caveat: harbor-hot's flow backends are still in-memory scaffolds (demo client, stub session, unsigned placeholder tokens), so the harness asserts flow *shape* + the §11.7 negatives resiliently rather than full token crypto — it tightens automatically as the real backends land.
3. **Coverage floor is set to 75%** (just below the current 78.8% baseline), enforced by the F5 `coverage-ratchet` under the ratchet-only-goes-up policy. Raise it further as coverage grows; never lower it.
4. **`CODEOWNERS` uses the placeholder `@harbor/maintainers`.** Set real owning handles before relying on branch protection.
5. **`tamper-check` and codegen-drift need git history** — they no-op / cannot run on a fresh clone with no upstream base ref or git; their teeth come from CI running them against the real PR base.
