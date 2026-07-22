> **DESIGN §8–9** · [↑ DESIGN index](../../DESIGN.md) · next: [data-model](data-model.md)

# Go Backend & Frontend Design

## 8. Go Backend Design

### 8.1 Recommended libraries

| Concern | Choice | Why |
|---|---|---|
| **OIDC OP** | **`zitadel/oidc`** | Actively maintained, purpose-built for building an OP (not just a client), supports the flows we need. (`ory/fosite` is the main alternative — powerful but lower-level/more work.) |
| **WebAuthn** | **`go-webauthn/webauthn`** | De-facto standard Go passkey library. |
| **DB access** | **`pgx`** + **`sqlc`** | `pgx` = fast native Postgres driver; `sqlc` = compile-time-checked typed queries from SQL. No heavy ORM on the hot path. |
| **REST codegen** | **`oapi-codegen`** | Generates Go server stubs + models from OpenAPI 3.1 (spec-first, see §1). |
| **gRPC codegen** | **`buf`** + `protoc-gen-go`/`-go-grpc` | Lint, breaking-change checks, and typed stubs from Protobuf. |
| **Migrations** | **`golang-migrate`** (or `goose`) | Simple, versioned SQL migrations. |
| **Cache** | **`redis`** + in-proc LRU (`hashicorp/golang-lru`) | Redis for shared short-TTL state; in-proc for JWKS/client metadata. |
| **Crypto** | stdlib `crypto` + cloud KMS SDK | Keep crypto boring and standard. |
| **Config/DI** | plain constructors + `viper`/env | Avoid magic. |

### 8.2 Project layout

```
harbor/
├── cmd/
│   ├── harbor-hot/        # auth-hot binary (OIDC/verify)
│   └── harbor-mgmt/       # management/dashboard API binary
├── internal/
│   ├── oidc/              # OP endpoints, token issuance
│   ├── webauthn/          # passkey register/assert
│   ├── mfa/               # TOTP, recovery codes, step-up
│   ├── identity/          # users, credentials, PPID derivation
│   ├── clients/           # RP registry, grants, consent
│   ├── audit/             # append-only auth events
│   ├── crypto/            # envelope encryption, signing, KMS
│   ├── cache/             # redis + in-proc
│   ├── region/            # region resolution/routing
│   ├── addons/ageproof/   # (future) verifiable credentials
│   └── gen/               # ALL generated code (never hand-edited); internal/ hides it from importers
│       ├── openapi/       # Go server/client from OpenAPI
│       ├── proto/         # Go gRPC stubs from Protobuf
│       └── db/            # sqlc-generated typed queries
├── db/
│   ├── migrations/
│   └── queries/           # sqlc source (SQL = the contract)
├── api/                   # CANONICAL CONTRACTS (source of truth, see §1)
│   ├── openapi/           # REST specs: dashboard/BFF, RP-mgmt, admin
│   ├── proto/             # internal gRPC service + message contracts
│   └── json-schema/       # shared data models ($ref'd by OpenAPI)
├── deploy/                # k8s manifests / helm per region
└── docs/
```

### 8.3 API styles (spec-first, see §1)

- **Protocol endpoints**: standard **OIDC/REST** (must be spec-compliant for RPs); validated against OIDC/WebAuthn **conformance suites**.
- **Internal service-to-service**: **gRPC**, contract defined in Protobuf under `api/proto/` and code-generated.
- **Dashboard / RP-management / admin APIs**: **REST**, contract defined in OpenAPI 3.1 under `api/openapi/`; Go server stubs and the TypeScript client are **both generated** from it, so backend and frontend never drift.
- GraphQL is intentionally avoided for now: REST keeps the security-sensitive surface small, easy to audit, and trivially spec-first.

## 9. Frontend Design

**Recommendation: Next.js (React) + TypeScript.**

- Largest ecosystem for WebAuthn/passkey UX, easiest to hire for, mature security patterns.
- Use it as a **BFF**: browser talks to Next.js server routes; secrets/tokens stay server-side in `HttpOnly` cookies (no tokens in `localStorage`).
- **Typed API client is generated from the backend's OpenAPI spec** (`openapi-typescript` / `orval`); the frontend **never hand-writes request/response types** (see §1.3). Change the spec → regenerate → the compiler flags every affected call site.
- Screens:
  - **Auth UI** (hosted by Harbor): login, passkey prompt, consent screen (shows exactly which claims an RP requests), step-up.
  - **Dashboard**: connected apps (view/revoke per-RP grants), sessions & devices (revoke), passkeys (add/remove), MFA & recovery setup, **audit log viewer + export**, data export/delete (GDPR).
- Zero third-party trackers/analytics in the auth + dashboard surfaces (consistency with the promise).

*(SvelteKit is a fine lighter alternative; React chosen for ecosystem/hiring and passkey library maturity.)*
