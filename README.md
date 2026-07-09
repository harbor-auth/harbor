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

## Documentation

- **[docs/DESIGN.md](docs/DESIGN.md)** — full system design: trust model, protocols, multi-jurisdiction routing, performance engineering, security, data model, user flows, compliance, roadmap, and key trade-offs.

## Roadmap (summary)

0. **MVP** — single region OIDC OP, passkey login, PPID, dashboard, GDPR self-serve.
1. **Performance** — split hot/cold paths, edge JWKS caching, load-test to millions/sec.
2. **Multi-jurisdiction** — second region, PII-free global control plane, edge routing.
3. **Trust & enterprise** — DPoP, social recovery, transparency log, third-party audit.
4. **Add-ons** — privacy-preserving age proof (verifiable credentials).

See [docs/DESIGN.md §14](docs/DESIGN.md) for details, and [§1](docs/DESIGN.md) for the engineering principles (standards/contract/codegen-first).
