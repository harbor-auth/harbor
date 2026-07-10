> **DESIGN §1.1–1.6** · [↑ DESIGN index](../../DESIGN.md) · next: [testing](testing.md)

# Engineering Principles — Standards, Contracts & Codegen

These principles govern *how* we build Harbor. They are as binding as the product pillars: an implementation that violates them is wrong even if it "works". The through-line is simple — **the specification is the source of truth, and as much as possible is generated from it.**

## 1.1 Standards & protocols first

We **never invent what an open standard already solves.** Identity, auth, crypto, and interchange are adversarial, high-stakes domains where rolling our own is how you get breached. For every capability we first ask *"what is the ratified standard, and is there a certified/compliant implementation?"* and adopt it.

The standards Harbor commits to:

| Domain | Standard(s) | Notes |
|---|---|---|
| Federation / SSO | **OpenID Connect (OIDC)**, **OAuth 2.1** | We are a certified OP; Authorization Code + PKCE only. |
| Authentication | **FIDO2 / WebAuthn / passkeys** | Primary, phishing-resistant factor. |
| MFA | **RFC 6238 TOTP** | Secondary factor. |
| Tokens / crypto | **JOSE**: JWT (RFC 7519), JWS, JWK/JWKS, JWA | ES256/EdDSA signing. |
| Verifiable claims (later) | **SD-JWT VC**, **W3C Verifiable Credentials 2.0**, **ISO/IEC 18013-5 mDL**, **eIDAS 2.0** | For the age-proof add-on. |
| REST interfaces | **OpenAPI 3.1** (a JSON Schema dialect) | Every REST surface. |
| Data schemas | **JSON Schema 2020-12** | Shared models; OpenAPI 3.1 reuses these. |
| Internal RPC | **Protobuf (proto3) + gRPC** | Typed service-to-service contracts. |
| Async / events (later) | **AsyncAPI** + schema registry | Event contracts. |
| Provisioning (enterprise, later) | **SCIM 2.0** | If/when we support directory sync. |
| Persistence | **SQL** | The query *is* the contract (via `sqlc`). |

Where a standard has an official **conformance/certification suite** (OIDC, WebAuthn), passing it is a release gate — not an afterthought.

## 1.2 Contract-first: every interface has a machine-readable spec

**Every interface in the system — external *and* internal — is defined by a versioned, machine-readable contract that is the single source of truth.** The contract is written or amended **before** the implementation, reviewed like code, and lives in-repo under `/api`.

- "Interface" means: the RP-facing protocol surface, the dashboard/BFF REST API, the RP-management and admin APIs, every internal gRPC service, every shared data model, every async event, and the DB access layer.
- Contracts are **heavily specified**: every field typed, constrained (formats, enums, ranges, required/optional), documented, and given examples. Vague `object`/`any` payloads are not allowed.
- Contracts are **versioned** (semver) and **backward-compatibility-checked** in CI. A breaking change is a deliberate, reviewed, major-version event.
- The contract, not the code, is authoritative. If code and spec disagree, the code is the bug.

## 1.3 Codegen everywhere

**Anything that can be generated from a spec (or from other code) is generated — never hand-written and never hand-maintained in parallel.** Hand-written code is reserved for genuine business logic that no generator can produce.

From each contract we generate, as applicable:

- **Server side:** request/response models, routing/handler stubs, input validation, and OpenAPI/proto-derived interfaces the business logic implements.
- **Client side:** typed SDKs and API clients (Go, TypeScript) so no consumer hand-writes request/response types.
- **Data layer:** typed, compile-time-checked query functions from SQL (`sqlc`).
- **Docs:** human-readable API reference rendered directly from the specs.
- **Test assets:** mocks, fake servers, and contract/fixture data for consumer-driven contract testing.

Generated code is **reproducible and CI-verified**: regenerating in CI must produce a clean `git diff`. Drift between spec and generated code fails the build. Generated files are clearly marked and never edited by hand.

## 1.4 The right spec language per interface (a deliberate refinement)

We want **OpenAPI-style rigor for every interface**, but we use the **native contract language best suited to each interface type** rather than forcing OpenAPI onto surfaces where a stronger native contract exists. This preserves the intent — heavily-defined, codegen-driven contracts everywhere — while staying idiomatic and honest.

| Interface | Contract language | Codegen tooling | Rationale |
|---|---|---|---|
| Dashboard / BFF REST, RP-management API, admin API | **OpenAPI 3.1** | `oapi-codegen` (Go), `openapi-typescript` / `orval` (TS), Redoc (docs) | Public REST → OpenAPI is the lingua franca; JSON-Schema-based. |
| Internal service-to-service | **Protobuf + gRPC** | `buf` + `protoc-gen-go`/`-go-grpc` | Faster, strictly typed, better evolution semantics than REST for internal calls. |
| Shared data models / value objects | **JSON Schema 2020-12** | shared `$ref`s into OpenAPI + type generators | One schema → Go + TS types + validation. |
| Protocol edge (OIDC, OAuth, WebAuthn) | **The standards themselves are the contract** | certified libs + **conformance suites** | We *conform to* and *test against* these specs; we do not redefine them. We publish an OpenAPI *facade* for discoverability only. |
| Database access | **SQL** (`.sql` files) | **`sqlc`** → typed Go | The query is the contract; compile-time checked. |
| Async / events (later) | **AsyncAPI** | AsyncAPI generators + schema registry | Event payloads get the same rigor as sync APIs. |
| Service configuration | **JSON Schema / CUE** | validated at process boot | Config is an interface too — typed and validated, fail-fast. |
| Frontend ↔ backend types | *generated from the OpenAPI above* | `openapi-typescript` | The web app **never hand-writes API types.** |

**Net rule:** OpenAPI for REST, Protobuf for gRPC, standard OIDC/WebAuthn at the protocol edge, SQL+`sqlc` for data — but **all of them are spec-first, heavily-contracted, and code-generated.**

## 1.5 Contract governance & CI enforcement

Contracts are only trustworthy if they're enforced. In CI we:

- **Lint** specs (`spectral` for OpenAPI, `buf lint` for proto) against a shared style guide.
- **Check backward compatibility** on every change (`oasdiff` for OpenAPI, `buf breaking` for proto); breaking changes require an explicit major-version bump and reviewer sign-off.
- **Verify codegen is current** — regenerate from specs and fail if the working tree changes (no drift).
- **Run conformance suites** — OIDC OP certification and WebAuthn conformance are release gates.
- **Contract-test** consumers against provider specs (mocks generated from the same source of truth).

## 1.6 Consequences for the design

- The `/api` directory (see §8.2) is the **canonical home** of all contracts (`openapi/`, `proto/`, `json-schema/`) and is reviewed with the same rigor as source code.
- New features start by **editing a spec**, then regenerating, then filling in business logic — in that order.
- Because one schema fans out to Go types, TS types, validation, docs, and mocks, the system stays **DRY across the entire stack**: change the contract once, everything downstream regenerates.
