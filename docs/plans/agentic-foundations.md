---
title: Agentic development foundations
status: promoted           # draft | approved | in-progress | promoted | abandoned
design_refs: [§1.8, §1.9, §2.2, §5.3, §5.4, §6.5.7, §11.7, §A.8]
targets: [flake.nix, Makefile, invariants/, internal/telemetry/, internal/arch/, tools/lint/, e2e/, .github/workflows/, .agents/ENTRYPOINT.md, CODEOWNERS]
promoted_to: features/agentic-foundations.md  # features/<slug>.md once implemented, else null
created: 2026-07-08        # date this plan was authored
---

# Agentic development foundations (plan)

## Problem

Harbor is built almost entirely by AI agents whose context windows truncate and who can (a) lose memory across sessions, (b) let crypto/security drift silently, (c) see green from checks that were actually *skipped*, (d) weaken checks to make them pass (Goodhart), and (e) misread log soup. Today the repo has no executable guardrails: the `Makefile` silently skips missing tools and exits `0`, there is no CI, no invariants registry, no frozen crypto vectors, no import-boundary tests, and no PII-in-telemetry guard. These are cheap to add now and painful to retrofit — the same day-one framing as §A.8.

## Proposed approach

Build 10 mutually-reinforcing foundations. Each turns a piece of DESIGN prose into an executable, agent-legible guardrail. They are ordered by dependency: the hermetic toolchain (F3) underlies structured output (F6) and CI (F7); the invariants registry (F1) is the keystone the others enforce.

| # | Foundation | Prevents (agent failure) | In this repo |
|---|---|---|---|
| 1 | **Executable Invariants Registry** (keystone) | invariants live as prose in 3 places; a reviewer-LLM can miss a regression | `invariants/registry.yaml` (one entry per §A.8 non-negotiable → `enforced_by` tests) + meta-test failing any invariant lacking a live `//harbor:invariant INV-XXX`-tagged test |
| 2 | **Golden Vector Corpus** (frozen) | silent crypto drift | hand-computed `internal/{identity,oidc}/testdata/*_vectors.json` (PPID HMAC, PKCE S256); byte-equality; tests never regenerate expectations; loud `VECTOR-CHANGE:` reminder |
| 3 | **Fail-Closed Hermetic Toolchain** | green-that-means-nothing | `flake.nix` pinning go, golangci-lint, sqlc, oapi-codegen, buf, spectral, migrate, k6 + rewrite Makefile `[skip]`→`exit 1` (human-only `SOFT=1` escape) |
| 4 | **Agent ENTRYPOINT + Context Map** | no memory | `.agents/ENTRYPOINT.md` (mandated first-read: hierarchy, the one trusted command, hard rules) + per-package `doc.go` mapping `internal/<domain>` → DESIGN § + invariants |
| 5 | **Anti-Goodhart Tamper Guards** | weakening checks to pass | `CODEOWNERS` on `invariants/`, `testdata/*vectors*`, `.github/`, `Makefile`; test-weakening detector (deleted tests / dropped tags / new `t.Skip`); coverage ratchet on identity/oidc/crypto; no naked `//nolint` |
| 6 | **Structured check output** | agents misread log soup | `make agent-check` → `check-results.json` (pass\|fail\|error, no skipped-counts-as-pass); identical local & CI verdict |
| 7 | **CI as the agent-readable outer loop** | the only loop an agent can't skip | `.github/workflows/ci.yml` runs `make agent-check` in the pinned toolchain; posts `check-results.json` as a sticky PR comment; branch protection gives F5 its teeth |
| 8 | **Agent-runnable local e2e OIDC harness** | unit-green but composed-flow broken | `e2e/docker-compose.yml` + `e2e/flow_test.go` driving authorize→token→JWKS incl. §11.7 negatives; feeds the conformance gate |
| 9 | **Architecture import-boundary fitness tests** | shortest-path coupling that kills SLOs/isolation | `internal/arch/arch_test.go`: `cmd/harbor-hot` must not import DB/pgx; only `internal/gen/**` is generated; region isolation import rules (§5.3) |
| 10 | **PII-in-telemetry deny-by-default guard** | "helpful" `log.Info("user", email)` breaks the core promise silently | `internal/telemetry` (sole allow-listed slog/OTel wrapper) + `tools/lint/piifields` analyzer in agent-check; allow-list CODEOWNERS-protected |

## DESIGN alignment

Realizes §1.9 (living toolkit) operationally and hard-enforces §A.8 (day-one mitigations), §11.7 (OIDC security invariants), §6.5.7 (telemetry privacy invariants), §5.3/§5.4 (region isolation / PII-free control plane), §2.2 (verifiable, not merely promised), and §1.8 (fast→slow CI stages). It does **NOT** change `DESIGN.md` — it makes existing invariants *executable* rather than aspirational. If any foundation would contradict the design, that is an explicit DESIGN change, not smuggled in here.

## Target code paths

Grouped by foundation (these become the feature doc's `code:` map on promotion):

- **F1** `invariants/registry.yaml`, `invariants/registry_test.go`
- **F2** `internal/identity/testdata/ppid_vectors.json`, `internal/identity/ppid_vectors_test.go`, `internal/oidc/testdata/pkce_vectors.json`, `internal/oidc/pkce_vectors_test.go`
- **F3** `flake.nix`, `flake.lock`, `Makefile`
- **F4** `.agents/ENTRYPOINT.md`, `internal/<domain>/doc.go` (identity, oidc, region, telemetry, arch)
- **F5** `CODEOWNERS`, `tools/lint/testweakening/`, coverage-ratchet target in `Makefile`
- **F6** `Makefile` (`agent-check`), `tools/agentcheck/` (emits `check-results.json`)
- **F7** `.github/workflows/ci.yml`
- **F8** `e2e/docker-compose.yml`, `e2e/flow_test.go`, `e2e/README.md`
- **F9** `internal/arch/arch_test.go`, `internal/arch/doc.go`
- **F10** `internal/telemetry/`, `tools/lint/piifields/`

## Implementation checklist

- [x] **F3 Fail-closed hermetic toolchain:** `flake.nix` pins the toolchain; Makefile missing-tool branches become `exit 1` with install hints; `SOFT=1` human-only escape.
- [x] **F1 Executable invariants registry:** `invariants/registry.yaml` with the 7 §A.8 non-negotiables; meta-test (`invariants/registry_test.go`) fails any invariant whose `enforced_by` test is missing or lacks a `//harbor:invariant INV-XXX` tag.
- [x] **F2 Golden vector corpus:** frozen `internal/identity/testdata/ppid_vectors.json` + `internal/oidc/testdata/pkce_vectors.json`; byte-equality tests that NEVER regenerate; `VECTOR-CHANGE:` guidance.
- [x] **F9 Architecture fitness tests:** `internal/arch/arch_test.go` (harbor-hot ⇏ pgx/db; region isolation; generated-only dir rules).
- [x] **F10 PII-in-telemetry guard:** `internal/telemetry` allow-listed slog wrapper + `tools/lint/piifields` analyzer wired into agent-check.
- [x] **F4 Agent ENTRYPOINT + context map:** `.agents/ENTRYPOINT.md` + per-package `doc.go` domain→§→invariant map.
- [x] **F6 Structured check output:** `make agent-check` emits `check-results.json` (pass|fail|error; skipped ≠ pass).
- [x] **F8 Agent-runnable e2e:** `e2e/docker-compose.yml` + `e2e/flow_test.go` (authorize→token→JWKS + §11.7 negatives).
- [x] **F5 Anti-Goodhart tamper guards:** `CODEOWNERS` + test-weakening detector + coverage ratchet.
- [x] **F7 CI outer loop:** `.github/workflows/ci.yml` runs agent-check in the pinned env + sticky PR comment.
- [x] **Tests/validation:** `go build ./...`, `go vet ./...`, `go test ./...` green; new meta-test/vector/arch/telemetry tests pass; `make agent-check` produces valid `check-results.json`.
- [x] **Reconcile & promote:** `@plan promote agentic-foundations` → creates the feature doc.

## Risks & open questions

- Nix adds a prerequisite for contributors — mitigated by the `SOFT=1` local escape and CI being the source of truth.
- The test-weakening detector needs a trusted baseline (git history) — start heuristic (grep for dropped `//harbor:invariant` tags / new `t.Skip` / deleted `_test.go`), harden later.
- Coverage-ratchet thresholds need a starting baseline measured from the current tests.
- `flake.lock` exact tool versions may need a follow-up `nix flake update` once real pins are chosen.

## Definition of done

`go build/vet/test ./...` green; `flake.nix` present and Makefile fail-closed with `SOFT=1` escape; invariants registry + meta-test enforce all 7 §A.8 non-negotiables; frozen vectors byte-match; arch + telemetry-PII guards fail on violation; `.agents/ENTRYPOINT.md` + per-package `doc.go` present; `make agent-check` emits `check-results.json`; CI workflow present; CODEOWNERS + tamper guards present. Ready to `@plan promote`.
