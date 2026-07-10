# Harbor

**Privacy-first, ethical Single Sign-On.** A tracking-free replacement for "Sign in with Google/Facebook".

Harbor is an OpenID Provider (OP) that authenticates people to the apps they've explicitly connected — and **nothing more**. No tracking, no profiling, no data selling. We're a neutral identity + auth broker that manages your passkeys, MFA, and logins.

## Principles

- **Verifiable privacy.** We technically constrain *ourselves* from tracking users. Pairwise pseudonymous identifiers (PPID) mean relying parties can't correlate you across apps — and neither can we.
- **Data sovereignty.** Each user lives in exactly one jurisdiction. Their data never leaves that region. Region is encoded in identifiers so requests route at the edge with no global lookup.
- **Extreme performance, low cost.** The sign-in / token-verification hot path is stateless and edge-cacheable (asymmetric JWTs verified via JWKS, no DB hit), so we can serve millions of verifications per second cheaply.
- **Standards-first, contract-first, codegen-everywhere.** We never invent what an open standard already solves, every interface (external *and* internal) is defined by a versioned machine-readable contract, and anything derivable from a spec is generated — not hand-maintained.

## Tech at a glance

| Layer | Choice |
|---|---|
| Core backend | **Go** (modular monolith; `zitadel/oidc`, `go-webauthn`, `pgx` + `sqlc`) |
| Auth factors | **Passkeys (WebAuthn)** primary; TOTP + recovery codes secondary |
| Protocols | **OIDC / OAuth 2.1 + PKCE**; SAML deferred |
| Data | **Postgres + Redis** per region; envelope encryption via regional KMS/HSM |
| Frontend | **Next.js (React) + TypeScript** dashboard & auth UI (typed API client generated from OpenAPI) |
| Contracts | **OpenAPI 3.1** (REST) · **Protobuf/gRPC** (internal) · **SQL + `sqlc`** (data) — spec-first, codegen-verified in CI |
| Deploy | **Kubernetes**, multi-jurisdiction, anycast/GeoDNS edge |

## Status

🚧 **Foundation / scaffolding.** The design is set and the codegen-first foundation is landing: spec-first API contracts (`api/openapi`, `api/proto`), the Go modular-monolith skeleton (`harbor-hot` / `harbor-mgmt` serving spec-generated OIDC discovery + health), the Postgres schema + migrations, PPID derivation (with a golden regression vector), and the `make generate` / `validate` / `test` toolchain wiring the `.agents/` skills. No production auth flows (`/authorize`, `/token`, passkeys) yet.

## Getting started

### Prerequisites

Harbor pins its entire toolchain (Go 1.26, `sqlc`, `oapi-codegen`, `buf`,
`golangci-lint`, `spectral`, `golang-migrate`, `k6`, Node/`pnpm`) with Nix so
local and CI runs are byte-identical. Enter the hermetic dev shell:

```bash
nix develop            # drops you into the pinned toolchain shell
```

Without Nix you need Go 1.26+ and Docker (for the e2e / conformance gates); the
`make` targets **fail closed** with an install hint when a required tool is
missing. Run `make help` to list every target.

### Build

```bash
make build             # compile ./... and build harbor-hot + harbor-mgmt into ./bin
make build-static      # static CGO-off linux/amd64 binaries for tiny images
```

### Test

```bash
make test              # unit tests
make test-race         # unit tests with the race detector
make test-cover        # unit tests with coverage
make test-integration  # integration tests (real Postgres/Redis; -tags=integration)
```

### Run

Harbor is a modular monolith split into two binaries (see
[docs/DESIGN.md](docs/DESIGN.md) §4.1).

**`harbor-hot`** — the stateless OIDC / token hot path (`/authorize`, `/token`,
`/jwks`, discovery, `/healthz`):

```bash
PORT=8080 \
ISSUER=http://localhost:8080 \
  go run ./cmd/harbor-hot          # or ./bin/harbor-hot after `make build`
```

| Env | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | Listen port. |
| `ISSUER` | `http://localhost:$PORT` | Issuer that anchors the discovery document. |

**`harbor-mgmt`** — the management / dashboard cold path plus the passkey
(WebAuthn) registration & assertion ceremonies:

```bash
PORT=8081 \
WEBAUTHN_RP_ID=localhost \
WEBAUTHN_RP_DISPLAY_NAME=Harbor \
WEBAUTHN_RP_ORIGINS=http://localhost:8081 \
  go run ./cmd/harbor-mgmt         # or ./bin/harbor-mgmt after `make build`
```

| Env | Default | Purpose |
|---|---|---|
| `PORT` | `8081` | Listen port. |
| `WEBAUTHN_RP_ID` | `localhost` | Relying Party ID (effective domain, no scheme/port). |
| `WEBAUTHN_RP_DISPLAY_NAME` | `Harbor` | Human-readable RP name. |
| `WEBAUTHN_RP_ORIGINS` | `http://localhost:$PORT` | Comma-separated allowed ceremony origins. |
| `WEBAUTHN_ALLOW_INSECURE_USER_ID` | `false` | **DEV ONLY** — trust a client-supplied `user_id`. Never enable in production. |

> **Scaffold status:** flow backends are in-memory / stubbed (demo client,
> auto-approving login/consent, unsigned placeholder tokens) so the flows are
> exercisable before the real registry, HSM signer, and auth UI land.

### Codegen & validation

Everything derivable from the `api/` contracts is generated, never
hand-maintained (spec-first, zero drift):

```bash
make generate          # regenerate Go/TS from api/openapi + api/proto + sqlc
make validate          # fmt, vet, lint, spec-lint, codegen-drift (fast inner loop)
make agent-check       # ALL checks -> check-results.json (the one trusted verdict, F6)
```

### Database migrations

```bash
make migrate        DATABASE_URL=postgres://…   # apply all pending migrations
make migrate-status DATABASE_URL=postgres://…   # show the current version
make migrate-down   DATABASE_URL=postgres://…   # roll back the last migration
```

### Conformance (release gate)

`make conformance` first runs the fast in-repo e2e OIDC smoke harness
(`e2e/docker-compose.yml` + `go test -tags=e2e ./e2e/...`), then the full OpenID
Foundation OP certification suite and the WebAuthn gate (requires Docker):

```bash
make conformance       # e2e smoke -> OIDF OP plan -> assert -> WebAuthn gate
```

The OIDF OP suite is intentionally **honest red** until harbor-hot reaches real
OIDC compliance (asymmetric-signed tokens, pairwise subjects) — details in
[conformance/README.md](conformance/README.md).

## Documentation

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — a one-page, high-level map (hot/cold path, regions, KMS) — start here.
- **[docs/DESIGN.md](docs/DESIGN.md)** — full system design: trust model, protocols, multi-jurisdiction routing, performance engineering, security, data model, user flows, compliance, roadmap, and key trade-offs.
- **[docs/README.md](docs/README.md)** — the feature/plan index (as-built capabilities and future work).

## Roadmap (summary)

0. **MVP** — single region OIDC OP, passkey login, PPID, dashboard, GDPR self-serve.
1. **Performance** — split hot/cold paths, edge JWKS caching, load-test to millions/sec.
2. **Multi-jurisdiction** — second region, PII-free global control plane, edge routing.
3. **Trust & enterprise** — DPoP, social recovery, transparency log, third-party audit.
4. **Add-ons** — privacy-preserving age proof (verifiable credentials).

See [docs/DESIGN.md §14](docs/DESIGN.md) for details, and [§1](docs/DESIGN.md) for the engineering principles (standards/contract/codegen-first).

## License

Harbor is a **multi-license monorepo** managed under the
[REUSE specification](https://reuse.software): the full text of every license
lives in [`LICENSES/`](LICENSES/), and the authoritative, machine-readable map is
[`REUSE.toml`](REUSE.toml) (verify with `reuse lint`).

Unless a file or subtree declares otherwise, everything is **AGPL-3.0-only**.
Per-subtree overrides:

| Path | License | Why |
|---|---|---|
| *(default)* | **AGPL-3.0-only** | Core server & identity code — network copyleft. |
| `api/` | **Apache-2.0** | Public OpenAPI / Protobuf contracts — permissive for broad client/SDK generation. |
| `docs/` | **CC-BY-4.0** | Documentation & prose — reusable with attribution. |
| `.agents/` | **MIT** | Agent skills & workflow tooling — maximally reusable. |
| `tools/` | **MIT** | Developer tooling. |

Copyright © 2026 The Harbor Authors.

> **Proprietary components** (e.g. deployment & billing) are kept as separate,
> independently-licensed works — their own subtree with its own `LICENSE` + SPDX
> headers, or a separate private repo — so the AGPL boundary stays explicit and
> auditable.
