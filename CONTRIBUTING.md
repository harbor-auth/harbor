# Contributing to Harbor

Thanks for your interest in Harbor — a privacy-first, ethical OpenID Provider.
This guide covers how to set up your environment, the conventions we hold
ourselves to, and how to get a change merged.

By participating you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md). Security issues should **not** be filed
as normal issues — see [SECURITY.md](SECURITY.md).

## Getting started

### Prerequisites

Harbor pins its entire toolchain with **Nix** so local and CI runs are
byte-identical:

```bash
nix develop            # drops you into the pinned toolchain shell
```

Without Nix you need **Go 1.26+** and **Docker** (for the e2e / conformance
gates). The `make` targets fail closed with an install hint when a required tool
is missing.

```bash
make help              # list every target
```

### Build

```bash
make build             # compile ./... and build harbor-hot + harbor-mgmt into ./bin
```

### Test & validate

```bash
make test              # unit tests
make test-race         # unit tests with the race detector
make validate          # fmt, vet, lint, spec-lint, codegen-drift (fast inner loop)
make agent-check       # ALL checks -> check-results.json (the one trusted verdict)
```

Run `make agent-check` before opening a PR — it is the exact command CI runs in
the same pinned toolchain, so a green local run is a green CI run.

## Code style & conventions

Harbor is **spec-first, contract-first, codegen-everywhere**:

- **Never invent what an open standard already solves.** Follow the relevant
  RFC / OIDC spec.
- **Contracts come before code.** The OpenAPI spec (`api/openapi`), Protobuf
  (`api/proto`), and SQL + `sqlc` queries (`db/`) are the source of truth.
- **Generated code is never hand-edited.** Anything under `internal/gen/**` is
  produced by `make generate`. Change the contract, then regenerate. CI's
  codegen-drift check (`make generate-check`) fails if generated output differs
  from its spec.
- Match the style, structure, and naming of the surrounding code.

### Executable invariants

Harbor's non-negotiable security properties (asymmetric-only tokens, PPID as
`sub`, hash-at-rest refresh tokens, fail-closed decrypt, exact redirect-URI
match, …) are encoded as **executable invariants** in
[`invariants/registry.yaml`](invariants/registry.yaml). Each is anchored to a
test tagged with a `//harbor:invariant INV-XXX` comment. A meta-test fails the
build if any registered invariant loses its enforcing test.

If your change touches auth or crypto, **do not remove or weaken these tags.**
Add new invariants when you add new security-critical guarantees.

### Protected paths (CODEOWNERS)

Certain paths — the invariants registry, the check definitions, the pinned
toolchain, CI config, frozen crypto golden vectors, the PII allow-list, and
`docs/DESIGN.md` — are guarded by [CODEOWNERS](CODEOWNERS). Changes there
require an explicit maintainer review so a check can never be quietly weakened
to "go green". Expect extra scrutiny on those files.

## Commits & Developer Certificate of Origin (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/).
Sign off every commit to certify you have the right to submit it:

```bash
git commit -s -m "feat(oidc): ..."
```

This appends a `Signed-off-by: Your Name <you@example.com>` trailer. Commits
without a sign-off will be asked to amend.

Use [Conventional Commits](https://www.conventionalcommits.org/) for the subject
line (e.g. `feat(...)`, `fix(...)`, `docs(...)`, `test(...)`, `chore(...)`).

## Pull request process

1. Fork and branch from `main`.
2. Make your change; keep it focused and minimal.
3. Ensure `make agent-check` is green locally.
4. Open a PR against `main` with a clear description of *what* and *why*.
5. CI must pass — both the **`agent-check`** and **`e2e`** jobs are required.
   The anti-tamper (F5) guards and CODEOWNERS reviews must also be satisfied.
6. A maintainer reviews and merges.

## Where to learn the design

- [**docs/ARCHITECTURE.md**](docs/ARCHITECTURE.md) — a one-page high-level map
  (hot/cold path, regions, KMS). Start here.
- [**docs/DESIGN.md**](docs/DESIGN.md) — the authoritative deep dive: trust
  model, protocols, routing, performance, security, data model, threat model.
- [**docs/README.md**](docs/README.md) — the feature / plan index.

Welcome aboard, and thank you for helping build authentication that respects
users. 🚢
