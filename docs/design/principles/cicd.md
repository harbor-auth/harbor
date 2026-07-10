> **DESIGN §1.8** · [↑ DESIGN index](../../DESIGN.md) · prev: [testing](testing.md) · next: [skills-and-small-files](skills-and-small-files.md)

# CI/CD, Fast Builds & Fast Local Validation

## 1.8 CI/CD, fast builds & fast local validation

**Core principle: fast feedback at every level.** Sub-second local syntax/lint feedback, fast per-system builds, and fast *independent* deploys — because velocity and safety **compound** (quick feedback catches mistakes while they're cheap, and small, frequent, reversible deploys make each change low-risk).

#### Fast local validation (the inner loop)

Developers get near-instant feedback **before** CI ever runs:

- **Editor/LSP (`gopls`)** surfaces syntax and type errors *as you type*.
- Fast local commands: `gofmt`/`goimports`, `go vet`, `golangci-lint`, spec-lint (`spectral` for OpenAPI, `buf lint` for proto), and the **codegen-drift check** (§1.5) — all runnable in seconds.
- **Pre-commit hooks** run the *fast subset* (format, vet, lint, secret-scan) on **changed files only**, so obviously-broken code never reaches CI. **Changed-files-only + caching** is the rule — the inner loop must stay sub-second-ish to be used.

#### Fast, independent per-system builds

- The modular monolith (§4.2) compiles into small, separately-deployable binaries — `harbor-hot`, `harbor-mgmt` (§8.2) — that build and ship **independently**.
- **Build caching** everywhere: Go build/test cache, Docker layer caching, and a shared remote cache in CI.
- **Affected-only builds:** only rebuild/redeploy the systems whose inputs actually changed. A dashboard change **does not** rebuild or redeploy the hot path.
- Small **static Go binaries** → tiny images → fast push/pull and fast rollouts.

#### CI pipeline stages (fast → slow, fail fast)

Cheap, high-signal checks run first and gate the expensive ones:

| # | Stage | Checks | Typical speed | Gates |
|---|---|---|---|---|
| 1 | Static | format · `go vet` · lint · spec-lint · **codegen-drift** | seconds | blocks all |
| 2 | Contract compat | breaking-change checks (`oasdiff`/`buf breaking`, §1.5) | seconds | blocks build |
| 3 | Fast tests | unit + contract (parallel, sharded) | seconds | blocks build |
| 4 | Build | compile binaries + images (cached) | seconds–min | blocks integration |
| 5 | Integration | per-system, real Postgres/Redis (service containers) | min | blocks merge |
| 6 | Security | SAST · dependency · secret scans | seconds–min | blocks merge |
| 7 | Conformance | OIDC OP + WebAuthn suites | s–min | blocks **release** |
| 8 | Load (pre-release) | hot-path throughput & p99 budgets | min | blocks release |

#### Independent, progressive deploys

- Each system deploys **independently** to Kubernetes (§6).
- **Per-region progressive delivery** (canary → progressive rollout) with **automated health checks** and **fast automated rollback** on regression.
- **DB migrations** run as a **gated, backward-compatible** step using **expand/contract**, so schema changes are decoupled from code deploys and each is independently reversible.
- **Region isolation (§5)** means a bad rollout is **contained to one jurisdiction** — never a global outage.

#### Trunk-based & always-releasable

- Short-lived branches, **small PRs**, `main` always green and deployable; **feature flags** hide incomplete work. This is the delivery cadence assumed by the phased roadmap (§14).
