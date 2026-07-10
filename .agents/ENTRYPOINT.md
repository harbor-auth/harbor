# Harbor — Agent ENTRYPOINT (read me first)

**This is the first file to read before doing anything in this repo.** It is the map: the one trusted command, the knowledge hierarchy, the hard rules you cannot break, and where each domain lives. Everything else is downstream of this page.

## The one trusted command

```bash
make agent-check
```

`make agent-check` is the **single source of truth** for "is it green?". It runs the full check suite (gofmt · build · vet · tests · invariants meta-test · PII-in-telemetry analyzer · golangci-lint · buf lint · docs-design-refs · docs-links), **fails closed** on any missing tool, and emits a structured verdict to `check-results.json` (Foundation F6). The verdict is identical locally and in CI. Because it now runs the pinned linters, the verdict is authoritative only inside the pinned toolchain (`nix develop`); codegen-drift runs in CI, not here, because it needs git history. Spectral (OpenAPI spec-lint) also runs as a separate CI-side step via pinned npx — nixpkgs removed the package, so it can no longer run inside the pinned shell.

- **Never** trust ad-hoc partial checks ("the one test I ran passed"). Run `make agent-check`.
- **Never** set `SOFT=1` — that is a *human-only* local escape hatch for a missing tool. Agents and CI must always fail closed.
- A check that was *skipped* is **not** a pass. `check-results.json` records `pass | fail | error` — never "skipped-counts-as-pass".

## The knowledge hierarchy

```
DESIGN.md (index)  → WHY + system-level WHAT — navigable § → file map (§0–§15)
   └─ docs/design/ → topic-focused design files (each ≤ ~2,000 words)
docs/plans/        → future WHAT — intent not yet built
   └─ docs/features/  → as-built WHAT + HOW — realized capabilities
        └─ code       → the ground truth for as-built behavior
```

- Start at [`docs/README.md`](../docs/README.md) (the feature & plan index) and [`.agents/README.md`](./README.md) (the skills & agents toolkit).
- **For a feature doc, the code is reality** — on drift, reconcile the *doc* to the *code* (`@docs reconcile`).
- **`DESIGN.md` is the design index.** A change to the design is **explicit**: open `DESIGN.md`, find the `§` in the map, and edit the owning file in `docs/design/`. Never smuggle design changes in via a plan, feature doc, or code.

## Hard rules (non-negotiable)

The security/privacy invariants are **executable**, not prose — see [`invariants/registry.yaml`](../invariants/registry.yaml) (each entry maps a §A.8/§11.7 non-negotiable to the test that enforces it; the meta-test fails the build if any invariant lacks a live, tagged test).

- **Asymmetric-only signing** — ES256/EdDSA only; reject `alg:none` and any HS/symmetric fallback (`INV-SIGN-ASYM-ONLY`, §3.3/§7.3).
- **PKCE S256 mandatory** for every client; `plain` rejected (`INV-PKCE-MANDATORY`, §11.2/§11.7).
- **Exact `redirect_uri` match** against a pre-registered allowlist; never act on an unvalidated redirect (`INV-REDIRECT-EXACT`, §11.7).
- **Single-use, short-TTL authorization codes**; reuse ⇒ `invalid_grant` (`INV-CODE-SINGLE-USE`, §3.5/§11.7).
- **Generic `invalid_grant`** — token failures never reveal which check failed (`INV-INVALID-GRANT-GENERIC`, §11.7).
- **Constant-time comparison** for codes/PKCE/secrets/tokens (`INV-CONSTANT-TIME-COMPARE`, §11.7).
- **Per-user pairwise secret** — no global correlation secret; sectors are non-correlating (`INV-PPID-PAIRWISE-SECRET`, §3.2).
- **No PII in telemetry** — no email/user_id/sub/PPID/IP/token in logs, metrics, or traces. Log through [`internal/telemetry`](../internal/telemetry) (deny-by-default allow-listing); the [`piifields`](../tools/lint/piifields) analyzer gates it (§6.5.7).
- **No bulk-decrypt capability** (structurally absent, §2.3) and **region isolation** — no cross-region PII/keys (§5.4).

> **Never weaken a check or delete/skip a test to go green.** The tamper guards (Foundation F5) + `CODEOWNERS` will catch a dropped `//harbor:invariant` tag, a new `t.Skip`, or a deleted test. **Fix the code, not the check.**

## Context map

Each domain maps to a DESIGN § and the invariants/tests that enforce it. Per-package `doc.go` files carry the detail.

| Package | DESIGN § | Enforced by |
|---|---|---|
| [`internal/identity`](../internal/identity) | §3.2 | `INV-PPID-PAIRWISE-SECRET`; frozen PPID golden vectors (`testdata/ppid_vectors.json`) |
| [`internal/oidc`](../internal/oidc) | §3.1, §11.7 | `INV-PKCE-MANDATORY`, `INV-REDIRECT-EXACT`, `INV-CODE-SINGLE-USE`, `INV-INVALID-GRANT-GENERIC`, `INV-CONSTANT-TIME-COMPARE`, `INV-SIGN-ASYM-ONLY`; frozen PKCE vectors |
| [`internal/oidcapi`](../internal/oidcapi) | §11.2 | spec-generated HTTP handlers wiring `internal/oidc`; e2e flow (F8) |
| [`internal/webauthn`](../internal/webauthn) | §3.1, §7.1 | passkey ceremony tests |
| [`internal/region`](../internal/region) | §5 | arch fitness test (region stays pure, §5.3/§5.4) |
| [`internal/telemetry`](../internal/telemetry) | §6.5.7 | `piifields` analyzer + wrapper tests |
| [`internal/arch`](../internal/arch) | §4.1, §5.3 | import-boundary fitness tests (hot path ⇏ DB) |

## Workflow

Skills and agents are the living toolkit — see [`.agents/README.md`](./README.md). The spine:

```
@plan (+ @openspec spec) → @build → @validate → @harbor-reviewer → @codegen → @github-flow
```

Every plan is paired with a formal OpenSpec change (`openspec/changes/<slug>/`) that must pass `openspec validate --strict` before build — see [`@openspec`](./openspec.md).

Use **`@hippo`** for cross-session memory: **recall first** at session start, and **capture friction as `hippo todo`** the moment it appears so nothing is lost when context truncates.

## Before you finish

- [ ] `make agent-check` is green (`check-results.json` overall = pass; no check `error`/`fail`/skipped).
- [ ] Invariants meta-test green — every invariant still has a live `//harbor:invariant`-tagged test.
- [ ] No new PII fields in any log/metric/trace (`piifields` clean; log through `internal/telemetry`).
- [ ] Docs reconciled — feature/plan index and affected `docs/features/*.md` match the code (`@docs reconcile`).
- [ ] `make docs-check` is green — every `design_refs §` resolves in `DESIGN.md`'s map **and** no relative links are broken. Run this whenever any file under `docs/` changes.

> **Update this file as the toolchain/workflow evolves — a stale entrypoint is a bug.**
