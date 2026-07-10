> **DESIGN §1.9–1.10** · [↑ DESIGN index](../../DESIGN.md) · prev: [cicd](cicd.md) · next: [error-handling](error-handling.md)

# Skills, Agents & the Small-Files Principle

## 1.9 Skills & agents (a living toolkit)

**Core principle: capture repeated work.** If we do something more than a couple of times, we turn it into a reusable **skill** (a documented workflow/checklist, invoked `@skill-name`) or, once it's frequent and stable, a **dedicated agent** (a specialized doer). This keeps our process fast, consistent, and hard to get wrong — the same way §1.7/§1.8 keep our *code* fast and consistent.

- **Modifying skills is first-class.** When we find an error, discover a better way, or the toolchain changes, we **update the skill immediately** — ideally in the same PR as the fix. Skills are versioned in-repo and reviewed like code. **A stale skill is a bug.**
- **When to create one:** a task repeated ≥3 times, a multi-step workflow that's easy to get wrong, or a checklist tied to these principles (privacy invariants, spec-first, testing, security).
- **Lifecycle:** identify repetition → draft skill → use it → refine on every friction → (optionally) promote to a dedicated agent.

The toolkit lives in **`.agents/`** (see `.agents/README.md` for the index and philosophy). Initial skills:

| Skill | Purpose |
|---|---|
| `go-build` | Build the Go binaries (`harbor-hot`, `harbor-mgmt`). |
| `go-test` | Go unit/integration tests, race detector, coverage (§1.7). |
| `frontend-test` | Next.js/TS typecheck, lint, unit tests (§9). |
| `validate` | Fast changed-files inner loop: fmt/vet/lint/spec-lint/codegen-drift (§1.8). |
| `db-migrate` | Postgres expand/contract migrations — backward-compatible, reversible (§1.8). |
| `codegen` | Regenerate all code from the `api/` contracts — spec-first, zero drift (§1.2–§1.5). |
| `code-review` | Review against Harbor's privacy/security/spec-first principles. |
| `oidc-conformance` | Run the OIDC OP + WebAuthn conformance suites as a hard release gate (§1.7, §1.8 Stage 7). |
| `load-test` | Hot-path throughput & p99 latency load tests as a pre-release gate (§1.8 Stage 8, §6.5.5). |

**First graduation in practice:** the `code-review` skill has already been promoted into a dedicated **`harbor-reviewer`** agent (`.agents/harbor-reviewer.ts`) — the privacy/security checklist baked in, delegating the general pass to `@deep-code-reviewer`. The old `@code-review` skill is now a thin pointer, proving the lifecycle above is real, not aspirational.

More will be added as the project grows (e.g. `db-seed`, `release`, `chaos-test`).

## 1.10 Small, single-concern files

**Core principle: each file targets exactly one feature or concern, and stays small.** A file should have one reason to exist and one reason to change. When something new but distinct shows up, it gets its own file — not another section bolted onto an existing one.

**Why (the practical reason):** small, focused files keep *both* humans and AI agents fast and accurate. A large file forces reading thousands of tokens of unrelated code just to touch one thing — wasting context and, for an agent, risking **context loops**: re-reading the same big file over and over without making progress. One concern per file means precise reads and precise edits.

- **Use packages to group, not bigger files.** Don't grow a file to hold related things — split by concern and let the **package** (Go package / TS module / directory) provide the grouping and boundary. This dovetails with §8's `internal/<domain>` layout, where each domain is a package of small, single-purpose files.
- **One primary responsibility per file.** Prefer one primary type/function-family per file; when a file starts mixing concerns or grows long, split it and reach for a **package boundary** rather than a larger file.
- **Co-locate focused tests.** Keep a file's test beside it (`ppid.go` ↔ `ppid_test.go`). Small, single-concern units are trivially testable without mocks — the same property §1.7 relies on (pure logic separated from I/O).

This is **enforced in review**: the `@harbor-reviewer` agent flags files that mix multiple concerns or grow large and suggests splitting them along a package boundary.
